import {
  createJWT,
  SimpleSigner,
  decodeJWT,
  verifyJWT,
  JWTVerified,
} from "did-jwt";
import { Resolver } from "did-resolver";
import VidDidResolver from "@validatedid/vid-did-resolver";
import { AxiosResponse } from "axios";
import {
  DidAuthRequestCall,
  DidAuthKeyAlgo,
  DidAuthRequestPayload,
  DidAuthResponsePayload,
  DidAuthResponseCall,
  DidAuthScope,
  DidAuthResponseType,
  DidAuthResponseIss,
  expirationTime,
  DidAuthValidationResponse,
  SignatureResponse,
} from "./interfaces/DIDAuth";
import DidAuthErrors from "./interfaces/Errors";
import { getNonce, doPostCallWithToken, getState } from "./util/Util";
import {
  JWTVerifyOptions,
  JWTHeader,
  EnterpriseAuthZToken,
} from "./interfaces/JWT";
import { util, JWK } from "./util";

export default class VidDidAuth {
  /**
   *
   * @param siopRequest
   */
  static async createUriRequest(
    didAuthRequestCall: DidAuthRequestCall
  ): Promise<{ uri: string; nonce: string; jwt: string }> {
    if (!didAuthRequestCall || !didAuthRequestCall.redirectUri)
      throw new Error(DidAuthErrors.BAD_PARAMS);
    const { jwt, nonce } = await VidDidAuth.createDidAuthRequest(
      didAuthRequestCall
    );
    const responseUri = `openid://?response_type=${DidAuthResponseType.ID_TOKEN}&client_id=${didAuthRequestCall.redirectUri}&scope=${DidAuthScope.OPENID_DIDAUTHN}&requestUri=${didAuthRequestCall.requestUri}`;
    // returns a URI with Request JWT embedded
    return { uri: responseUri, nonce, jwt };
  }

  /**
   * Creates a DidAuth Request Object
   * @param didAuthRequestCall Request input data to build a signed DidAuth Request Token
   */
  static async createDidAuthRequest(
    didAuthRequestCall: DidAuthRequestCall
  ): Promise<{ jwt: string; nonce: string }> {
    if (!didAuthRequestCall || !didAuthRequestCall.redirectUri)
      throw new Error(DidAuthErrors.BAD_PARAMS);
    if (!didAuthRequestCall.signatureUri)
      throw new Error(DidAuthErrors.KEY_SIGNATURE_URI_ERROR);
    if (!didAuthRequestCall.authZToken)
      throw new Error(DidAuthErrors.AUTHZTOKEN_UNDEFINED);
    const payload: DidAuthRequestPayload = this.createDidAuthRequestPayload(
      didAuthRequestCall
    );
    // signs payload calling the provided signatureUri
    const jwt = await this.signDidAuthExternal(
      payload,
      didAuthRequestCall.signatureUri,
      didAuthRequestCall.authZToken
    );
    return { jwt, nonce: payload.nonce };
  }

  /**
   * Verifies a DidAuth ID Request Token
   * @param didAuthJwt signed DidAuth Request Token
   * @param registry hexadecimal ddress where it is deployed the VID DID Smart Contract
   * @param rpcUrl URL for the VID DID Provider
   */
  static async verifyDidAuthRequest(
    didAuthJwt: string,
    registry: string,
    rpcUrl: string
  ): Promise<DidAuthRequestPayload> {
    // as audience is set in payload as a DID, it is required to be set as options
    const options: JWTVerifyOptions = {
      audience: util.getAudience(didAuthJwt),
      resolver: new Resolver(
        VidDidResolver.getResolver({
          rpcUrl,
          registry,
        })
      ),
    };
    const verifiedJWT: JWTVerified = await verifyJWT(didAuthJwt, options);
    if (!verifiedJWT || !verifiedJWT.payload)
      throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    return verifiedJWT.payload as DidAuthRequestPayload;
  }

  /**
   * Creates a DidAuth Response Object
   * @param input Response input data to build a signed DidAuth Response Token
   */
  static async createDidAuthResponse(
    didAuthResponseCall: DidAuthResponseCall
  ): Promise<string> {
    if (
      !didAuthResponseCall ||
      !didAuthResponseCall.hexPrivatekey ||
      !didAuthResponseCall.did ||
      !didAuthResponseCall.nonce ||
      !didAuthResponseCall.redirectUri
    )
      throw new Error(DidAuthErrors.BAD_PARAMS);

    const payload: DidAuthResponsePayload = this.createDidAuthResponsePayload(
      didAuthResponseCall
    );
    // signs payload using internal libraries
    const jwt = await this.signDidAuthInternal(
      didAuthResponseCall.did,
      payload,
      didAuthResponseCall.hexPrivatekey
    );
    return jwt;
  }

  /**
   * Verifies a DidAuth ID Response Token
   * @param didAuthJwt igned DidAuth Response Token
   * @param nonce nonce value sent in the Authentication Request
   */
  static async verifyDidAuthResponse(
    didAuthJwt: string,
    verifyUri: string,
    authZToken: string,
    nonce: string
  ): Promise<DidAuthValidationResponse> {
    const data = {
      jws: didAuthJwt,
    };
    try {
      const response: AxiosResponse = await doPostCallWithToken(
        verifyUri,
        data,
        authZToken
      );
      if (!response || !response.status || response.status !== 204)
        throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    } catch (error) {
      throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    }

    const { payload } = decodeJWT(didAuthJwt);
    if (payload.nonce !== nonce)
      throw Error(DidAuthErrors.ERROR_VALIDATING_NONCE);

    return {
      signatureValidation: true,
    };
  }

  private static createDidAuthRequestPayload(
    input: DidAuthRequestCall
  ): DidAuthRequestPayload {
    const { payload } = decodeJWT(input.authZToken);
    return {
      iss: (payload as EnterpriseAuthZToken).did,
      scope: DidAuthScope.OPENID_DIDAUTHN,
      registration: {
        jwks_uri: `${
          (payload as EnterpriseAuthZToken).did
        };transform-keys=jwks`,
        id_token_signed_response_alg: DidAuthKeyAlgo.ES256K,
      },
      response_type: DidAuthResponseType.ID_TOKEN,
      client_id: input.redirectUri,
      nonce: getNonce(),
      state: getState(),
      claims: input.claims,
    };
  }

  private static createDidAuthResponsePayload(
    input: DidAuthResponseCall
  ): DidAuthResponsePayload {
    return {
      iss: DidAuthResponseIss.SELF_ISSUE,
      sub: JWK.getThumbprint(input.hexPrivatekey),
      aud: input.redirectUri,
      nonce: input.nonce,
      sub_jwk: JWK.getJWK(input.hexPrivatekey, `${input.did}#key-1`),
      did: input.did,
      vp: input.vp,
    };
  }

  static async signDidAuthInternal(
    issuer: string,
    payload: DidAuthResponsePayload,
    hexPrivateKey: string
  ): Promise<string> {
    // assign specific JWT header
    const header: JWTHeader = {
      alg: DidAuthKeyAlgo.ES256KR,
      typ: "JWT",
      kid: `${issuer}#key-1`,
    };
    const response = await createJWT(
      payload,
      {
        issuer: DidAuthResponseIss.SELF_ISSUE,
        alg: DidAuthKeyAlgo.ES256KR,
        signer: SimpleSigner(hexPrivateKey.replace("0x", "")), // Removing 0x from private key as input of SimpleSigner
        expiresIn: expirationTime,
      },
      header
    );
    return response;
  }

  static async signDidAuthExternal(
    payload: DidAuthRequestPayload,
    signatureUri: string,
    authZToken: string
  ): Promise<string> {
    const data = {
      issuer: payload.iss,
      payload,
      type: "EcdsaSecp256k1Signature2019", // fixed type
      expiresIn: expirationTime,
    };
    const response = await doPostCallWithToken(signatureUri, data, authZToken);
    if (
      !response ||
      !response.status ||
      (response.status !== 200 && response.status !== 201) ||
      !response.data ||
      !(response.data as SignatureResponse).jws
    )
      throw new Error(DidAuthErrors.MALFORMED_SIGNATURE_RESPONSE);
    return (response.data as SignatureResponse).jws;
  }
}
