import { createJWT, SimpleSigner, decodeJWT, verifyJWT } from "did-jwt";
import { Resolver } from "did-resolver";
import VidDidResolver from "@validatedid/vid-did-resolver";
import { AxiosResponse } from "axios";
import { util, JWK } from "./util";
import DidAuthErrors from "./interfaces/Errors";
import { getNonce, doPostCallWithToken, getState } from "./util/Util";
import { JWTHeader, JWTVerifyOptions } from "./interfaces/JWT";
import {
  DidAuthKeyAlgorithm,
  DidAuthRequestOpts,
  DidAuthRequestPayload,
  DidAuthResponseIss,
  DidAuthResponseOpts,
  DidAuthResponsePayload,
  DidAuthResponseType,
  DidAuthScope,
  expirationTime,
  ExternalSignature,
  InternalSignature,
  ObjectPassedBy,
  RegistrationJwks,
  RegistrationJwksUri,
  RegistrationType,
  SignatureResponse,
  InternalVerification,
  ExternalVerification,
  DidAuthValidationResponse,
  DidAuthVerifyOpts,
} from "./interfaces/DIDAuth.types";
import { getPublicJWKFromPrivateHex } from "./util/JWK";

const isInternalSignature = (
  object: InternalSignature | ExternalSignature
): object is InternalSignature => {
  return "hexPrivateKey" in object && "did" in object;
};

const isExternalSignature = (
  object: InternalSignature | ExternalSignature
): object is ExternalSignature => {
  return "signatureUri" in object && "did" in object;
};

const isInternalVerification = (
  object: InternalVerification | ExternalVerification
): object is InternalVerification => {
  return "registry" in object && "rpcUrl" in object;
};

const isExternalVerification = (
  object: InternalVerification | ExternalVerification
): object is ExternalVerification => {
  return "verifyUri" in object;
};

const createRegistration = (
  registrationType: RegistrationType,
  signatureType: InternalSignature | ExternalSignature
): RegistrationJwksUri | RegistrationJwks => {
  if (!registrationType || !registrationType.type)
    throw new Error(DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);

  let registration: RegistrationJwksUri | RegistrationJwks;

  switch (registrationType.type) {
    case ObjectPassedBy.REFERENCE:
      if (!registrationType.referenceUri)
        throw new Error(DidAuthErrors.NO_REFERENCE_URI);
      registration = {
        jwks_uri: registrationType.referenceUri,
        id_token_signed_response_alg: DidAuthKeyAlgorithm.ES256K,
      };
      return registration;
    case ObjectPassedBy.VALUE:
      if (!isInternalSignature(signatureType))
        throw new Error("Option not implemented");
      registration = {
        jwks: getPublicJWKFromPrivateHex(
          signatureType.hexPrivateKey,
          signatureType.kid || `${signatureType.did}#key-1`
        ),
      };
      return registration;
    default:
      throw new Error(DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  }
};

const createDidAuthRequestPayload = (
  opts: DidAuthRequestOpts
): DidAuthRequestPayload => {
  const state = opts.state || getState();
  const registration = createRegistration(
    opts.registrationType,
    opts.signatureType
  );
  return {
    iss: opts.signatureType.did,
    scope: DidAuthScope.OPENID_DIDAUTHN,
    registration,
    client_id: opts.redirectUri,
    nonce: opts.nonce || getNonce(state),
    state,
    response_type: DidAuthResponseType.ID_TOKEN,
    response_mode: opts.responseMode,
    response_context: opts.responseContext,
    claims: opts.claims,
  };
};

const signDidAuthInternal = async (
  payload: DidAuthRequestPayload | DidAuthResponsePayload,
  issuer: string,
  hexPrivateKey: string,
  kid?: string
): Promise<string> => {
  // assign specific JWT header
  const header: JWTHeader = {
    alg: DidAuthKeyAlgorithm.ES256KR,
    typ: "JWT",
    kid: kid || `${issuer}#key-1`,
  };
  const response = await createJWT(
    payload,
    {
      issuer,
      alg: DidAuthKeyAlgorithm.ES256KR,
      signer: SimpleSigner(hexPrivateKey.replace("0x", "")), // Removing 0x from private key as input of SimpleSigner
      expiresIn: expirationTime,
    },
    header
  );
  return response;
};

const signDidAuthExternal = async (
  payload: DidAuthRequestPayload | DidAuthResponsePayload,
  signatureUri: string,
  authZToken: string
): Promise<string> => {
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
};

const createDidAuthResponsePayload = (
  opts: DidAuthResponseOpts
): DidAuthResponsePayload => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.signatureType ||
    !opts.nonce ||
    !opts.did
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);
  if (!isInternalSignature(opts.signatureType))
    throw new Error("Option not implemented");
  return {
    iss: DidAuthResponseIss.SELF_ISSUE,
    sub: JWK.getThumbprint(opts.signatureType.hexPrivateKey),
    nonce: opts.nonce,
    aud: opts.redirectUri,
    sub_jwk: JWK.getPublicJWKFromPrivateHex(
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid || `${opts.signatureType.did}#key-1`
    ),
    did: opts.did,
    vp: opts.vp,
  };
};

const verifyDidAuth = async (
  jwt: string,
  opts: DidAuthVerifyOpts
): Promise<DidAuthValidationResponse> => {
  if (!jwt || !opts || !opts.verificationType)
    throw new Error(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  if (isInternalVerification(opts.verificationType)) {
    const { rpcUrl } = opts.verificationType;
    const { registry } = opts.verificationType;
    // as audience is set in payload as a DID, it is required to be set as options
    const options: JWTVerifyOptions = {
      audience: util.getAudience(jwt),
      resolver: new Resolver(
        VidDidResolver.getResolver({
          rpcUrl,
          registry,
        })
      ),
    };
    // !!! TODO: adapt this verifyJWT to be able to admit issuer and aud as an http
    const verifiedJWT = await verifyJWT(jwt, options);
    if (!verifiedJWT || !verifiedJWT.payload)
      throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    const payload = verifiedJWT.payload as DidAuthRequestPayload;
    return { signatureValidation: true, payload };
  }
  if (isExternalVerification(opts.verificationType)) {
    const data = {
      jws: jwt,
    };
    try {
      const response: AxiosResponse = await doPostCallWithToken(
        opts.verificationType.verifyUri,
        data,
        opts.verificationType.authZToken
      );

      if (!response || !response.status || response.status !== 204)
        throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    } catch (error) {
      throw Error(
        DidAuthErrors.ERROR_VERIFYING_SIGNATURE + (error as Error).message
      );
    }

    return {
      signatureValidation: true,
    };
  }
  throw Error(DidAuthErrors.VERIFICATION_METHOD_NOT_SUPPORTED);
};

export {
  isInternalSignature,
  isExternalSignature,
  createDidAuthRequestPayload,
  signDidAuthInternal,
  signDidAuthExternal,
  createDidAuthResponsePayload,
  isInternalVerification,
  isExternalVerification,
  verifyDidAuth,
};
