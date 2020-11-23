import axios, { AxiosResponse } from "axios";
import { ebsiVerifyJwt, createJwt, SimpleSigner } from "@cef-ebsi/did-jwt";
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
import { DIDDocument } from "./interfaces/oidcSsi";
import { JWKECKey } from "./interfaces/JWK";

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

const createRegistration = async (
  registrationType: RegistrationType,
  signatureType: InternalSignature | ExternalSignature
): Promise<RegistrationJwksUri | RegistrationJwks> => {
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
      if (isInternalSignature(signatureType)) {
        registration = {
          jwks: getPublicJWKFromPrivateHex(
            signatureType.hexPrivateKey,
            signatureType.kid || `${signatureType.did}#keys-1`
          ),
        };
        return registration;
      }
      if (isExternalSignature(signatureType)) {
        // referenceUri will always be set on an external signature
        const getResponse = await axios.get(registrationType.referenceUri);
        if (!getResponse || !getResponse.data)
          throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
        const didDoc = getResponse.data as DIDDocument;
        if (
          !didDoc.verificationMethod ||
          !didDoc.verificationMethod[0] ||
          !didDoc.verificationMethod[0].publicKeyJwk
        )
          throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
        registration = {
          jwks: didDoc.verificationMethod[0].publicKeyJwk,
        };
        return registration;
      }
      throw new Error(DidAuthErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);
    default:
      throw new Error(DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  }
};

const createDidAuthRequestPayload = async (
  opts: DidAuthRequestOpts
): Promise<DidAuthRequestPayload> => {
  const state = opts.state || getState();
  const registration = await createRegistration(
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
    kid: kid || `${issuer}#keys-1`,
  };
  const response = await createJwt(
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

const createDidAuthResponsePayload = async (
  opts: DidAuthResponseOpts
): Promise<DidAuthResponsePayload> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.signatureType ||
    !opts.nonce ||
    !opts.did
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);
  if (
    !isInternalSignature(opts.signatureType) &&
    !isExternalSignature(opts.signatureType)
  )
    throw new Error(DidAuthErrors.SIGNATURE_OBJECT_TYPE_NOT_SET);

  // eslint-disable-next-line @typescript-eslint/naming-convention
  let sub_jwk: JWKECKey;
  let sub: string;

  if (isInternalSignature(opts.signatureType)) {
    sub = JWK.getThumbprint(opts.signatureType.hexPrivateKey);
    sub_jwk = JWK.getPublicJWKFromPrivateHex(
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid || `${opts.signatureType.did}#keys-1`
    );
  }
  if (isExternalSignature(opts.signatureType)) {
    if (!opts.registrationType || !opts.registrationType.referenceUri)
      throw new Error(DidAuthErrors.NO_REFERENCE_URI);
    const getResponse = await axios.get(opts.registrationType.referenceUri);
    if (!getResponse || !getResponse.data)
      throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
    const didDoc = getResponse.data as DIDDocument;
    if (
      !didDoc.verificationMethod &&
      !didDoc.verificationMethod[0] &&
      !didDoc.verificationMethod[0].publicKeyJwk
    )
      throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);

    sub_jwk = didDoc.verificationMethod[0].publicKeyJwk;
    sub = JWK.getThumbprintFromJwk(sub_jwk);
  }

  return {
    iss: DidAuthResponseIss.SELF_ISSUE,
    sub,
    nonce: opts.nonce,
    aud: opts.redirectUri,
    sub_jwk,
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
    // if audience it is a DID, it needs to be set as options audience
    // if not, it needs to be set as a callback url
    const audience = util.getAudience(jwt);
    const options: JWTVerifyOptions = {
      audience,
      resolver: await util.getUrlResolver(jwt, opts.verificationType),
      callbackUrl:
        audience !== undefined && !audience.match(/^did:/g)
          ? audience
          : undefined,
    };

    const verifiedJWT = await ebsiVerifyJwt(jwt, options);
    if (!verifiedJWT || !verifiedJWT.payload)
      throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    const payload = verifiedJWT.payload as DidAuthRequestPayload;
    return { signatureValidation: true, payload };
  }
  // external verification
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
};

export {
  isInternalSignature,
  isExternalSignature,
  createDidAuthRequestPayload,
  signDidAuthInternal,
  signDidAuthExternal,
  createDidAuthResponsePayload,
  isInternalVerification,
  verifyDidAuth,
};
