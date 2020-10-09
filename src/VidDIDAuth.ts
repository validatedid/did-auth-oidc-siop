import { createJWT, SimpleSigner, decodeJWT, verifyJWT } from "did-jwt";
import { Resolver } from "did-resolver";
import { createHash } from "crypto";
import {
  DidAuthRequestCall,
  DIDAUTH_KEY_ALGO,
  DIDAUTH_KEY_TYPE,
  DIDAUTH_KEY_CURVE,
  DidAuthRequestPayload,
  DidAuthResponsePayload,
  DidAuthResponseCall,
  DIAUTHScope,
  DIAUTHResponseType,
  DIDAUTH_RESPONSE_ISS,
  expirationTime,
  DidAuthValidationResponse,
} from "./DIDAuth";
import DIDAUTH_ERRORS from "./Errors";
import {
  getNonce,
  doPostCallWithToken,
  getECKeyfromHexPrivateKey,
  base64urlEncodeBuffer,
} from "./util/Util";
import { VerifiedJwt, JWTVerifyOptions, JWTHeader } from "./JWT";

import * as JWK from "./util/JWK";

const VidDidResolver = require("@validated-id/vid-did-resolver");

export default class VidDidAuth {
  /**
   *
   * @param siopRequest
   */
  static async createUriRequest(
    didAuthRequestCall: DidAuthRequestCall
  ): Promise<{ uri: string; nonce: string, jwt: string }> {
    if (!didAuthRequestCall || !didAuthRequestCall.redirectUri)
      throw new Error(DIDAUTH_ERRORS.BAD_PARAMS);
    const { jwt, nonce } = await VidDidAuth.createDidAuthRequest(
      didAuthRequestCall
    );
    const responseUri = `openid://&scope=${DIAUTHScope.OPENID_DIDAUTHN}?response_type=${DIAUTHResponseType.ID_TOKEN}&client_id=${didAuthRequestCall.redirectUri}&requestUri=${didAuthRequestCall.requestUri}`;
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
      throw new Error(DIDAUTH_ERRORS.BAD_PARAMS);
    if (!didAuthRequestCall.signatureUri)
      throw new Error(DIDAUTH_ERRORS.KEY_SIGNATURE_URI_ERROR);
    if (!didAuthRequestCall.authZToken)
      throw new Error(DIDAUTH_ERRORS.AUTHZTOKEN_UNDEFINED);
      console.log("didAuthrequestPayload");
    const payload: DidAuthRequestPayload = this.createDidAuthRequestPayload(
      didAuthRequestCall
    );
    console.log("didAuthrequestPayload2");
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
   * @param registry hexadecimal ddress where it is deployed the EBSI DID Smart Contract
   * @param rpcUrl URL for the EBSI DID Provider
   */
  static async verifyDidAuthRequest(
    didAuthJwt: string,
    registry: string,
    rpcUrl: string
  ): Promise<DidAuthRequestPayload> {
    // as audience is set in payload as a DID, it is required to be set as options
    const options: JWTVerifyOptions = {
      audience: this.getAudience(didAuthJwt),
      resolver: new Resolver(
        VidDidResolver.getResolver({
          rpcUrl,
          registry,
        })
      ),
    };
    const verifiedJWT: VerifiedJwt = await verifyJWT(didAuthJwt, options);
    if (!verifiedJWT || !verifiedJWT.payload)
      throw Error(DIDAUTH_ERRORS.ERROR_VERIFYING_SIGNATURE);
    return verifiedJWT.payload;
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
      throw new Error(DIDAUTH_ERRORS.BAD_PARAMS);

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
      const response = await doPostCallWithToken(verifyUri, data, authZToken);
      if (!response || !response.status || response.status !== 204)
        throw Error(DIDAUTH_ERRORS.ERROR_VERIFYING_SIGNATURE);
    } catch (error) {
      throw Error(DIDAUTH_ERRORS.ERROR_VERIFYING_SIGNATURE);
    }

    const { payload } = decodeJWT(didAuthJwt);
    if (payload.nonce !== nonce)
      throw Error(DIDAUTH_ERRORS.ERROR_VALIDATING_NONCE);

    return {
      signatureValidation: true,
    };
  }

  private static createDidAuthRequestPayload(
    input: DidAuthRequestCall
  ): DidAuthRequestPayload {
    const { payload } = decodeJWT(input.authZToken);
    return {
      iss: payload.did,
      scope: DIAUTHScope.OPENID_DIDAUTHN,
      response_type: DIAUTHResponseType.ID_TOKEN,
      client_id: input.redirectUri,
      nonce: getNonce(),
    };
  }

  private static createDidAuthResponsePayload(
    input: DidAuthResponseCall
  ): DidAuthResponsePayload {
    return {
      iss: DIDAUTH_RESPONSE_ISS.SELF_ISSUE,
      sub: this.getThumbprint(input.hexPrivatekey),
      aud: input.redirectUri,
      nonce: input.nonce,
      sub_jwk: this.getJWK(input.hexPrivatekey, `${input.did}#key-1`),
    };
  }

  static async signDidAuthInternal(
    issuer: string,
    payload: DidAuthResponsePayload,
    hexPrivateKey: string
  ): Promise<string> {
    // assign specific JWT header
    const header: JWTHeader = {
      alg: DIDAUTH_KEY_ALGO.ES256KR,
      typ: "JWT",
      kid: `${issuer}#key-1`,
    };
    const response = await createJWT(
      payload,
      {
        issuer: DIDAUTH_RESPONSE_ISS.SELF_ISSUE,
        alg: DIDAUTH_KEY_ALGO.ES256KR,
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
      (response.status !== 200 &&
      response.status !== 201) ||
      !response.data ||
      !response.data.jws
    )
      throw new Error(DIDAUTH_ERRORS.MALFORMED_SIGNATURE_RESPONSE);
    return response.data.jws;
  }

  private static getJWK(hexPrivateKey: string, kid?: string): JWK.JWKECKey {
    const { x, y } = getECKeyfromHexPrivateKey(hexPrivateKey);
    return {
      kid,
      kty: DIDAUTH_KEY_TYPE.EC,
      crv: DIDAUTH_KEY_CURVE.SECP256k1,
      x,
      y,
    };
  }

  private static getThumbprint(hexPrivateKey: string): string {
    const jwk = this.getJWK(hexPrivateKey);
    const fields = {
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    };
    const thumbprint = base64urlEncodeBuffer(
      createHash("sha256").update(JSON.stringify(fields)).digest()
    );
    return thumbprint;
  }

  static getAudience(jwt: string): string | undefined {
    const { payload } = decodeJWT(jwt);
    if (!payload) throw new Error(DIDAUTH_ERRORS.NO_AUDIENCE);
    if (!payload.aud) return undefined;
    if (Array.isArray(payload.aud))
      throw new Error(DIDAUTH_ERRORS.INVALID_AUDIENCE);
    return payload.aud;
  }
}
