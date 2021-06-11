import axios, { AxiosResponse } from "axios";
import { JWK } from "jose/types";
import jwtVerify from "jose/jwt/verify";
import { parseJwk } from "jose/jwk/parse";
import { verifyJWT, createJWT, ES256KSigner, EdDSASigner } from "did-jwt";
import { JWTVerifyOptions } from "did-jwt/lib/JWT";
import { DIDDocument } from "did-resolver";
import base58 from "bs58";
import { keyUtils } from "@transmute/did-key-ed25519";
import { util, utilJwk } from "./util";
import DidAuthErrors from "./interfaces/Errors";
import { getNonce, doPostCallWithToken, getState } from "./util/Util";
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
  NoSignature,
  ObjectPassedBy,
  RegistrationJwks,
  RegistrationJwksUri,
  RegistrationType,
  SignatureResponse,
  InternalVerification,
  ExternalVerification,
  DidAuthValidationResponse,
  DidAuthVerifyOpts,
  DidAuthKeyCurve,
  DidAuthResponseOptsNoSignature,
} from "./interfaces/DIDAuth.types";
import {
  getPublicJWKFromPrivateHex,
  getPublicJWKFromPublicHex,
} from "./util/JWK";
import { DEFAULT_PROOF_TYPE, PROOF_TYPE_EDDSA } from "./config";

const isInternalSignature = (
  object: InternalSignature | ExternalSignature | NoSignature
): object is InternalSignature => "hexPrivateKey" in object && "did" in object;

const isExternalSignature = (
  object: InternalSignature | ExternalSignature | NoSignature
): object is ExternalSignature => "signatureUri" in object && "did" in object;

const isNoSignature = (
  object: InternalSignature | ExternalSignature | NoSignature
): object is NoSignature => "hexPublicKey" in object && "did" in object;

const isInternalVerification = (
  object: InternalVerification | ExternalVerification
): object is InternalVerification => "registry" in object && "rpcUrl" in object;

const createRegistration = async (
  registrationType: RegistrationType,
  signatureType: InternalSignature | ExternalSignature | NoSignature
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
        id_token_signed_response_alg: registrationType.referenceUri.includes(
          "did:key:z6Mk"
        )
          ? DidAuthKeyAlgorithm.EDDSA
          : DidAuthKeyAlgorithm.ES256K,
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
      if (isNoSignature(signatureType)) {
        registration = {
          jwks: getPublicJWKFromPublicHex(
            signatureType.hexPublicKey,
            signatureType.kid || `${signatureType.did}#keys-1`,
            signatureType.did
          ),
        };
        return registration;
      }
      if (isExternalSignature(signatureType)) {
        // referenceUri will always be set on an external signature
        try {
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
        } catch (error) {
          throw new Error(
            `${
              DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT
            } Error: ${JSON.stringify(error, null, 2)}`
          );
        }
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
  let defaultAlgorithm = DidAuthKeyAlgorithm.ES256K;
  if (
    issuer.includes("did:key:z6Mk") ||
    (payload.sub_jwk &&
      (payload.sub_jwk as JWK).crv &&
      (payload.sub_jwk as JWK).crv === DidAuthKeyCurve.ED25519)
  )
    defaultAlgorithm = DidAuthKeyAlgorithm.EDDSA;
  const response = await createJWT(
    payload,
    {
      issuer,
      alg:
        defaultAlgorithm === DidAuthKeyAlgorithm.EDDSA
          ? DidAuthKeyAlgorithm.EDDSA
          : DidAuthKeyAlgorithm.ES256K,
      signer:
        defaultAlgorithm === DidAuthKeyAlgorithm.EDDSA
          ? EdDSASigner(
              Buffer.from(
                base58.decode(
                  keyUtils.privateKeyBase58FromPrivateKeyHex(hexPrivateKey)
                )
              ).toString("base64")
            )
          : ES256KSigner(hexPrivateKey.replace("0x", "")), // Removing 0x from private key as input of SimpleSigner
      expiresIn: expirationTime,
    },
    {
      typ: "JWT",
      alg:
        defaultAlgorithm === DidAuthKeyAlgorithm.EDDSA
          ? DidAuthKeyAlgorithm.EDDSA
          : DidAuthKeyAlgorithm.ES256K,
      kid:
        kid ||
        `${
          issuer === DidAuthResponseIss.SELF_ISSUE
            ? (payload.did as string)
            : issuer
        }#keys-1`,
    }
  );
  return response;
};

const signDidAuthExternal = async (
  payload: DidAuthRequestPayload | DidAuthResponsePayload,
  signatureUri: string,
  authZToken: string,
  kid?: string
): Promise<string> => {
  let defaultAlgorithm = DidAuthKeyAlgorithm.ES256K;
  if (payload.did && (payload.did as string).includes("did:key:z6Mk"))
    defaultAlgorithm = DidAuthKeyAlgorithm.EDDSA;
  if (payload.iss && payload.iss.includes("did:key:z6Mk"))
    defaultAlgorithm = DidAuthKeyAlgorithm.EDDSA;

  const data = {
    issuer: payload.iss.includes("did:") ? payload.iss : payload.did,
    payload,
    type:
      defaultAlgorithm === DidAuthKeyAlgorithm.EDDSA
        ? PROOF_TYPE_EDDSA
        : DEFAULT_PROOF_TYPE,
    expiresIn: expirationTime,
    alg:
      defaultAlgorithm === DidAuthKeyAlgorithm.EDDSA
        ? DidAuthKeyAlgorithm.EDDSA
        : DidAuthKeyAlgorithm.ES256K,
    selfIssued: payload.iss.includes(DidAuthResponseIss.SELF_ISSUE)
      ? payload.iss
      : undefined,
    kid,
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
  let sub_jwk: JWK;
  let sub: string;

  if (isInternalSignature(opts.signatureType)) {
    sub = utilJwk.getThumbprint(opts.signatureType.hexPrivateKey, opts.did);
    sub_jwk = utilJwk.getPublicJWKFromPrivateHex(
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid || `${opts.signatureType.did}#keys-1`,
      opts.did
    );
  }
  if (isExternalSignature(opts.signatureType)) {
    if (!opts.registrationType || !opts.registrationType.referenceUri)
      throw new Error(DidAuthErrors.NO_REFERENCE_URI);
    try {
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
      sub = opts.did.includes("did:key:z6Mk")
        ? utilJwk.getThumbprintFromJwkDidKey(sub_jwk)
        : utilJwk.getThumbprintFromJwk(sub_jwk);
    } catch (error) {
      throw new Error(
        `${DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT} Error: ${JSON.stringify(
          error,
          null,
          2
        )}`
      );
    }
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

const createDidAuthResponsePayloadNoSignature = async (
  opts: DidAuthResponseOptsNoSignature
): Promise<DidAuthResponsePayload> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.identifiersUri ||
    !opts.nonce ||
    !opts.did
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);

  // eslint-disable-next-line @typescript-eslint/naming-convention
  let sub_jwk: JWK;
  let sub: string;

  if (!opts.identifiersUri) throw new Error(DidAuthErrors.NO_IDENTIFIERS_URI);
  try {
    const getResponse = await axios.get(opts.identifiersUri);
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
    sub = opts.did.includes("did:key:z6Mk")
      ? utilJwk.getThumbprintFromJwkDidKey(sub_jwk)
      : utilJwk.getThumbprintFromJwk(sub_jwk);
  } catch (error) {
    throw new Error(
      `${DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT} Error: ${JSON.stringify(
        error,
        null,
        2
      )}`
    );
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
      audience: audience?.match(/^did:/g) ? audience : undefined,
      resolver: await util.getUrlResolver(jwt, opts.verificationType),
      callbackUrl:
        audience !== undefined && !audience.match(/^did:/g)
          ? audience
          : undefined,
    };
    const did = util.getIssuerDid(jwt);
    const { payload, header } = util.parseJWT(jwt);
    if (payload.iss === DidAuthResponseIss.SELF_ISSUE) {
      const didDocumentResult = await util.resolveDid(
        did,
        opts.verificationType.didUrlResolver
      );
      const { didDocument } = didDocumentResult;
      if (
        !didDocument ||
        !didDocument.verificationMethod ||
        !didDocument.verificationMethod[0].publicKeyJwk
      )
        throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);

      const publicKey = await parseJwk(
        didDocument.verificationMethod[0].publicKeyJwk,
        header.alg
      );
      try {
        const verificationWithJose = await jwtVerify(jwt, publicKey); // DO NOT SUPPORT ES256K-R
        return {
          signatureValidation: true,
          payload: verificationWithJose.payload as DidAuthRequestPayload,
        };
      } catch (error) {
        throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
      }
    }

    const verifiedJWT = await verifyJWT(jwt, options);
    if (!verifiedJWT || !verifiedJWT.payload)
      throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    return {
      signatureValidation: true,
      payload: verifiedJWT.payload as DidAuthRequestPayload,
    };
  }

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
  isNoSignature,
  createDidAuthRequestPayload,
  signDidAuthInternal,
  signDidAuthExternal,
  createDidAuthResponsePayload,
  isInternalVerification,
  verifyDidAuth,
  createDidAuthResponsePayloadNoSignature,
};
