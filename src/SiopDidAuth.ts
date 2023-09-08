import { DIDDocument } from "did-resolver";
import axios from "axios";
import { decodeJWT } from "did-jwt";
import { decodeJwt, decodeProtectedHeader } from "jose";
import {
  DidAuthRequestOpts,
  UriResponse,
  DidAuthResponseOpts,
  DidAuthValidationResponse,
  DidAuthRequestResponse,
  DidAuthVerifyOpts,
  UriRequest,
  ObjectPassedBy,
  DidAuthResponseType,
  DidAuthScope,
  UrlEncodingFormat,
  DidAuthResponseMode,
  DidAuthResponsePayload,
  DidAuthResponseIss,
  DidAuthRequestPayload,
  DidAuthKeyAlgorithm,
  DidAuthResponseOptsNoSignature,
} from "./interfaces/DIDAuth.types";
import { DidAuthErrors } from "./interfaces";
import {
  isInternalSignature,
  isExternalSignature,
  createDidAuthRequestPayload,
  signDidAuthInternal,
  signDidAuthExternal,
  createDidAuthResponsePayload,
  verifyDidAuth,
  createDidAuthResponsePayloadNoSignature,
} from "./AuxDidAuth";
import { VID_RESOLVE_DID_URL } from "./config";
import { util } from "./util";
import { JWTHeader } from "./interfaces/JWT";
import { getThumbprintFromJwk, getThumbprintFromJwkDidKey } from "./util/JWK";

/**
 * Creates a didAuth Request Object
 * @param opts Request input data to build a signed DidAuth Request Token
 */
const createDidAuthRequestObject = async (
  opts: DidAuthRequestOpts
): Promise<DidAuthRequestPayload> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.requestObjectBy ||
    !opts.registrationType
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);
  if (
    opts.requestObjectBy.type !== ObjectPassedBy.REFERENCE &&
    opts.requestObjectBy.type !== ObjectPassedBy.VALUE
  )
    throw new Error(DidAuthErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  if (
    opts.requestObjectBy.type === ObjectPassedBy.REFERENCE &&
    !opts.requestObjectBy.referenceUri
  )
    throw new Error(DidAuthErrors.NO_REFERENCE_URI);

  if (
    opts.registrationType.type !== ObjectPassedBy.REFERENCE &&
    opts.registrationType.type !== ObjectPassedBy.VALUE
  )
    throw new Error(DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET);
  if (
    opts.registrationType.type === ObjectPassedBy.REFERENCE &&
    !opts.registrationType.referenceUri
  )
    throw new Error(DidAuthErrors.NO_REFERENCE_URI);

  const didAuthRequestPayload = await createDidAuthRequestPayload(opts);
  return didAuthRequestPayload;
};

/**
 * Creates a didAuth Request Object
 * @param opts Request input data to build a signed DidAuth Request Token
 */
const createDidAuthRequest = async (
  opts: DidAuthRequestOpts
): Promise<DidAuthRequestResponse> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.requestObjectBy ||
    !opts.signatureType ||
    !opts.registrationType
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);
  if (
    !isInternalSignature(opts.signatureType) &&
    !isExternalSignature(opts.signatureType)
  )
    throw new Error(DidAuthErrors.BAD_SIGNATURE_PARAMS);

  const didAuthRequestPayload = await createDidAuthRequestObject(opts);
  const { nonce, state } = didAuthRequestPayload;

  if (isInternalSignature(opts.signatureType)) {
    return {
      jwt: await signDidAuthInternal(
        didAuthRequestPayload,
        opts.signatureType.did,
        opts.signatureType.hexPrivateKey,
        opts.signatureType.kid
      ),
      nonce,
      state,
    };
  }
  // signs payload calling the provided signatureUri
  return {
    jwt: await signDidAuthExternal(
      didAuthRequestPayload,
      opts.signatureType.signatureUri,
      opts.signatureType.authZToken,
      opts.signatureType.kid
    ),
    nonce,
    state,
  };
};

/**
 * Creates a didAuth Response Object, aka, id_token
 * @param opts Response input data to build a signed didAuth Response Token
 */
const createDidAuthResponse = async (
  opts: DidAuthResponseOpts
): Promise<string> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.signatureType ||
    !opts.registrationType
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);
  if (
    !isInternalSignature(opts.signatureType) &&
    !isExternalSignature(opts.signatureType)
  )
    throw new Error(DidAuthErrors.BAD_SIGNATURE_PARAMS);

  const didAuthResponsePayload: DidAuthResponsePayload =
    await createDidAuthResponsePayload(opts);

  if (isInternalSignature(opts.signatureType)) {
    return signDidAuthInternal(
      didAuthResponsePayload,
      DidAuthResponseIss.SELF_ISSUE,
      opts.signatureType.hexPrivateKey,
      opts.signatureType.kid
    );
  }
  // signs payload calling the provided signatureUri
  return signDidAuthExternal(
    didAuthResponsePayload,
    opts.signatureType.signatureUri,
    opts.signatureType.authZToken,
    opts.signatureType.kid
  );
};

const createDidAuthResponseObject = async (
  opts: DidAuthResponseOptsNoSignature
): Promise<DidAuthResponsePayload> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.registrationType ||
    !opts.identifiersUri
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);

  const didAuthResponsePayload: DidAuthResponsePayload =
    await createDidAuthResponsePayloadNoSignature(opts);
  return didAuthResponsePayload;
};

/**
 * Creates an URI Request
 * @param opts Options to define the Uri Request
 */
const createUriRequest = async (
  opts: DidAuthRequestOpts
): Promise<UriRequest> => {
  if (!opts || !opts.redirectUri || !opts.requestObjectBy)
    throw new Error(DidAuthErrors.BAD_PARAMS);
  if (
    opts.requestObjectBy.type !== ObjectPassedBy.REFERENCE &&
    opts.requestObjectBy.type !== ObjectPassedBy.VALUE
  )
    throw new Error(DidAuthErrors.REQUEST_OBJECT_TYPE_NOT_SET);
  if (
    opts.requestObjectBy.type === ObjectPassedBy.REFERENCE &&
    !opts.requestObjectBy.referenceUri
  )
    throw new Error(DidAuthErrors.NO_REFERENCE_URI);
  const { jwt, state, nonce } = await createDidAuthRequest(opts);

  const baseOidp = opts.oidpUri ? `${opts.oidpUri}?` : "";
  let responseUri = `${baseOidp}openid://?response_type=${DidAuthResponseType.ID_TOKEN}&client_id=${opts.redirectUri}&scope=${DidAuthScope.OPENID_DIDAUTHN}&state=${state}&nonce=${nonce}`;

  // returns an URI, with a reference Uri, and JWT
  if (opts.requestObjectBy.type === ObjectPassedBy.REFERENCE) {
    responseUri += `&requestUri=${opts.requestObjectBy.referenceUri}`;
    return {
      urlEncoded: encodeURI(responseUri),
      encoding: UrlEncodingFormat.FORM_URL_ENCODED,
      jwt,
    };
  }
  // returns an URI with Request JWT embedded
  responseUri += `&request=${jwt}`;
  return {
    urlEncoded: encodeURI(responseUri),
    encoding: UrlEncodingFormat.FORM_URL_ENCODED,
  };
};

/**
 * Creates an URI Request
 * @param opts Options to define the Uri Request
 */
const createUriRequestFromJwt = (
  jwt: string,
  payload: DidAuthRequestPayload,
  opts: DidAuthRequestOpts
): UriRequest => {
  if (
    !jwt ||
    !payload ||
    !payload.client_id ||
    !payload.nonce ||
    !payload.state
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);

  const baseOidp = opts.oidpUri ? `${opts.oidpUri}?` : "";
  let responseUri = `${baseOidp}openid://?response_type=${DidAuthResponseType.ID_TOKEN}&client_id=${payload.client_id}&scope=${DidAuthScope.OPENID_DIDAUTHN}&state=${payload.state}&nonce=${payload.nonce}`;

  // returns an URI, with a reference Uri, and JWT
  if (opts.requestObjectBy.type === ObjectPassedBy.REFERENCE) {
    responseUri += `&requestUri=${opts.requestObjectBy.referenceUri}`;
    return {
      urlEncoded: encodeURI(responseUri),
      encoding: UrlEncodingFormat.FORM_URL_ENCODED,
      jwt,
    };
  }
  // returns an URI with Request JWT embedded
  responseUri += `&request=${jwt}`;
  return {
    urlEncoded: encodeURI(responseUri),
    encoding: UrlEncodingFormat.FORM_URL_ENCODED,
  };
};

/**
 * Creates an URI Response
 * @param opts Options to define the Uri Response
 */
const createUriResponse = async (
  opts: DidAuthResponseOpts
): Promise<UriResponse> => {
  if (
    !opts ||
    !opts.redirectUri ||
    !opts.signatureType ||
    !opts.nonce ||
    !opts.state ||
    !opts.registrationType
  )
    throw new Error(DidAuthErrors.BAD_PARAMS);

  const idToken = await createDidAuthResponse(opts);
  // building the Response URI
  const params = `id_token=${idToken}&state=${opts.state}`;
  const uriResponse: UriResponse = {
    urlEncoded: "",
    encoding: UrlEncodingFormat.FORM_URL_ENCODED,
    response_mode: opts.responseMode,
  };

  switch (opts.responseMode) {
    case DidAuthResponseMode.FORM_POST:
      uriResponse.urlEncoded = encodeURI(opts.redirectUri);
      uriResponse.bodyEncoded = encodeURI(params);
      return uriResponse;
    case DidAuthResponseMode.QUERY:
      uriResponse.urlEncoded = encodeURI(`${opts.redirectUri}?${params}`);
      return uriResponse;
    // FRAGMENT is the default
    default:
      uriResponse.response_mode = DidAuthResponseMode.FRAGMENT;
      uriResponse.urlEncoded = encodeURI(`${opts.redirectUri}#${params}`);
      return uriResponse;
  }
};

/**
 * Verifies a DidAuth ID Request Token
 * @param requestJwt signed DidAuth Request Token
 * @param opts Verify options to use internal or external verification method
 */
const verifyDidAuthRequest = async (
  jwt: string,
  opts?: DidAuthVerifyOpts
): Promise<DidAuthValidationResponse> => {
  if (!jwt) throw new Error(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  const { header, payload } = decodeJWT(jwt);
  // Resolve the DID Document from the RP's DID specified in the iss request parameter.
  const resolverUrl =
    opts.verificationType.didUrlResolver || VID_RESOLVE_DID_URL;
  const issuerDid = util.getIssuerDid(jwt);
  let didDoc: DIDDocument;
  try {
    const response = await axios.get(`${resolverUrl}/${issuerDid}`);
    if (!response || !response.data)
      throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
    didDoc = response.data as DIDDocument;
  } catch (error) {
    throw new Error(
      `${DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT} : ${
        (error as Error).message
      }`
    );
  }

  // If jwks_uri is present, ensure that the DID in the jwks_uri matches the DID in the iss claim.
  if (
    util.hasJwksUri(payload as DidAuthRequestPayload) &&
    !util.DidMatchFromJwksUri(payload as DidAuthRequestPayload, issuerDid)
  )
    throw new Error(DidAuthErrors.ISS_DID_NOT_JWKS_URI_DID);

  // Determine the verification method from the RP's DID Document that matches the kid of the SIOP Request.
  const verificationMethod = util.getVerificationMethod(
    (header as JWTHeader).kid,
    didDoc
  );
  if (!verificationMethod)
    throw new Error(DidAuthErrors.VERIFICATION_METHOD_NOT_MATCHES);
  try {
    // Verify the SIOP Request according to the verification method above.
    const verification = await util.verifySignatureFromVerificationMethod(
      jwt,
      verificationMethod
    );
    if (!verification) throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
  } catch (error) {
    throw Error(
      DidAuthErrors.ERROR_VERIFYING_SIGNATURE + (error as Error).message
    );
  }

  // Additionally performs a complete token validation via vidVerifyJwt
  return verifyDidAuth(jwt, opts);
};

/**
 * Verifies an id_token result of a DID Auth Response
 * @param id_token signed didAuth Response Token
 * @param opts Verify options to use internal or external verification method
 */
const verifyDidAuthResponse = async (
  id_token: string,
  opts: DidAuthVerifyOpts
): Promise<DidAuthValidationResponse> => {
  if (!id_token || !opts || !opts.nonce || !opts.redirectUri)
    throw new Error(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  // The Client MUST validate that the value of the iss (issuer) Claim is https://self-isued.me.
  const payload = decodeJwt(id_token);
  const header = decodeProtectedHeader(id_token);
  // const { header, payload } = decodeJWT(id_token);

  if (
    !Object.values(DidAuthResponseIss).includes(
      payload.iss as DidAuthResponseIss
    )
  )
    throw new Error(DidAuthErrors.NO_SELFISSUED_ISS);
  // The Client MUST validate that the aud (audience) Claim contains the value of the
  // redirect_uri that the Client sent in the Authentication Request as an audience.
  if (payload.aud !== opts.redirectUri)
    throw new Error(DidAuthErrors.REPONSE_AUD_MISMATCH_REDIRECT_URI);
  // Resolve the DID Document from the SIOP's DID specified in the did claim.
  const resolverUrl =
    opts.verificationType.didUrlResolver || VID_RESOLVE_DID_URL;
  const issuerDid = util.getIssuerDid(id_token);
  // when sub_jwk.kid is like "did:ethr:0x9C28b8A941e14f17832D5cABd426D65E7DD02311#keys-1"
  // it can be resolved as a regular DID Doc
  // when it is a key thumbprint like "kid": "zcia2OVav6TYlsEqRosUUjFRQwJiLI/qT1dn4zDcaoU="
  // it requires a DID Document request witn jwks key transformation
  const tranformKeysUrl =
    payload.sub_jwk &&
    !(payload as DidAuthResponsePayload).sub_jwk.kid.includes("did:")
      ? ";transform-keys=jwks"
      : "";
  let didDoc: DIDDocument;
  try {
    const url = `${resolverUrl}/${issuerDid}${tranformKeysUrl}`;
    const response = await axios.get(
      `${resolverUrl}/${issuerDid}${tranformKeysUrl}`
    );
    if (!response || !response.data)
      throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
    didDoc = response.data as DIDDocument;
  } catch (error) {
    throw new Error(
      `${DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT} : ${
        (error as Error).message
      }`
    );
  }

  // If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and
  // its value checked to verify that it is the same value as the one that was sent in the Authentication Request.
  if (payload.nonce !== opts.nonce)
    throw Error(DidAuthErrors.ERROR_VALIDATING_NONCE);

  const verificationMethod = (payload as DidAuthResponsePayload).sub_jwk
    ? util.getVerificationMethod(
        (payload as DidAuthResponsePayload).sub_jwk.kid,
        didDoc
      )
    : didDoc.verificationMethod[0];

  if ((payload as DidAuthResponsePayload).sub_jwk) {
    // Determine the verification method from the SIOP's DID Document that matches the kid
    // of the sub_jwk claim in the id_token.
    if (!verificationMethod)
      throw new Error(DidAuthErrors.VERIFICATION_METHOD_NOT_MATCHES);
    // The Client MUST validate that the sub Claim value is the base64url encoded representation
    // of the thumbprint of the key in the sub_jwk Claim.
    const subClaim =
      header.alg === DidAuthKeyAlgorithm.EDDSA
        ? getThumbprintFromJwkDidKey(
            (payload as DidAuthResponsePayload).sub_jwk
          )
        : getThumbprintFromJwk((payload as DidAuthResponsePayload).sub_jwk);
    if (subClaim !== payload.sub)
      throw new Error(DidAuthErrors.JWK_THUMBPRINT_MISMATCH_SUB);
  }

  // The alg value SHOULD be the default of RS256. It MAY also be ES256.
  // In addition to RS256, an SIOP according to this specification MUST support EdDSA and ES256K.
  // --> https://identity.foundation/did-siop/#generate-siop-request
  // Note: this library implements only ES256
  if (
    header.alg !== DidAuthKeyAlgorithm.ES256K &&
    header.alg !== DidAuthKeyAlgorithm.ES256KR &&
    header.alg !== DidAuthKeyAlgorithm.EDDSA &&
    header.alg !== DidAuthKeyAlgorithm.ES256
  )
    throw new Error(DidAuthErrors.NO_ALG_SUPPORTED_YET);

  // The Client MUST validate the signature of the ID Token according to JWS [JWS]
  // using the algorithm specified in the alg Header Parameter of the JOSE Header,
  // using the key in the sub_jwk Claim; the key is a bare key in JWK format (not an X.509 certificate value).
  // SIOP: Verify the id_token according to the verification method above.
  // Verifying that the id_token was signed by the key specified in the sub_jwk claim.
  const verification = await util.verifySignatureFromVerificationMethod(
    id_token,
    verificationMethod
  );
  if (!verification) throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
  // Additionally performs a complete token validation via vidVerifyJwt
  // const validationResponse = await verifyDidAuth(id_token, opts);

  return {
    signatureValidation: verification,
    payload: payload as DidAuthResponsePayload,
  };
};

export {
  createUriRequest,
  createUriRequestFromJwt,
  createDidAuthRequestObject,
  createUriResponse,
  createDidAuthRequest,
  createDidAuthResponse,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
  createDidAuthResponseObject,
};
