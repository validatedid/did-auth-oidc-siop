import { decodeJwt } from "@validatedid/did-jwt";
import axios from "axios";
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
} from "./AuxDidAuth";
import VID_RESOLVE_DID_URL from "./config";
import { util } from "./util";
import { DIDDocument } from "./interfaces/oidcSsi";
import { JWTHeader } from ".";

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
    !isInternalSignature(opts.signatureType) &&
    !isExternalSignature(opts.signatureType)
  )
    throw new Error(DidAuthErrors.BAD_SIGNATURE_PARAMS);
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
      opts.signatureType.authZToken
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

  const didAuthResponsePayload: DidAuthResponsePayload = await createDidAuthResponsePayload(
    opts
  );

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
    opts.signatureType.authZToken
  );
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
      urlEncoded: encodeURIComponent(responseUri),
      encoding: UrlEncodingFormat.FORM_URL_ENCODED,
      jwt,
    };
  }
  // returns an URI with Request JWT embedded
  responseUri += `&request=${jwt}`;
  return {
    urlEncoded: encodeURIComponent(responseUri),
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
      uriResponse.urlEncoded = encodeURIComponent(opts.redirectUri);
      uriResponse.bodyEncoded = encodeURIComponent(params);
      return uriResponse;
    case DidAuthResponseMode.QUERY:
      uriResponse.urlEncoded = encodeURIComponent(
        `${opts.redirectUri}?${params}`
      );
      return uriResponse;
    // FRAGMENT is the default
    default:
      uriResponse.response_mode = DidAuthResponseMode.FRAGMENT;
      uriResponse.urlEncoded = encodeURIComponent(
        `${opts.redirectUri}#${params}`
      );
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
  opts: DidAuthVerifyOpts
): Promise<DidAuthValidationResponse> => {
  if (!jwt || !opts || !opts.verificationType)
    throw new Error(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  const { header, payload } = decodeJwt(jwt);
  // Resolve the DID Document from the RP's DID specified in the iss request parameter.
  const resolverUrl =
    opts.verificationType.didUrlResolver || VID_RESOLVE_DID_URL;
  const issuerDid = util.getIssuerDid(jwt);
  const response = await axios.get(`${resolverUrl}/${issuerDid}`);
  if (!response || response.data)
    throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
  const didDoc = response.data as DIDDocument;

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

  // Verify the SIOP Request according to the verification method above.
  if (!util.verifySignatureFromVerificationMethod(jwt, verificationMethod))
    return {
      signatureValidation: false,
    };
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
  if (
    !id_token ||
    !opts ||
    !opts.verificationType ||
    !opts.nonce ||
    !opts.redirectUri
  )
    throw new Error(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  // The Client MUST validate that the value of the iss (issuer) Claim is https://self-isued.me.
  const { header, payload } = decodeJwt(id_token);
  if (payload.iss !== DidAuthResponseIss.SELF_ISSUE)
    throw new Error(DidAuthErrors.NO_SELFISSUED_ISS);
  // The Client MUST validate that the aud (audience) Claim contains the value of the
  // redirect_uri that the Client sent in the Authentication Request as an audience.
  if (payload.aud !== opts.redirectUri)
    throw new Error(DidAuthErrors.REPONSE_AUD_MISMATCH_REDIRECT_URI);
  // Resolve the DID Document from the SIOP's DID specified in the did claim.
  const resolverUrl =
    opts.verificationType.didUrlResolver || VID_RESOLVE_DID_URL;
  const issuerDid = util.getIssuerDid(id_token);
  const response = await axios.get(`${resolverUrl}/${issuerDid}`);
  if (!response || response.data)
    throw new Error(DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT);
  const didDoc = response.data as DIDDocument;
  // Determine the verification method from the SIOP's DID Document that matches the kid
  // of the sub_jwk claim in the id_token.
  if (
    !(payload as DidAuthResponsePayload).sub_jwk ||
    !(payload as DidAuthResponsePayload).sub_jwk.kid
  )
    throw new Error(DidAuthErrors.SUB_JWK_NOT_FOUND_OR_NOT_KID);
  const verificationMethod = util.getVerificationMethod(
    (payload as DidAuthResponsePayload).sub_jwk.kid,
    didDoc
  );
  if (!verificationMethod)
    throw new Error(DidAuthErrors.VERIFICATION_METHOD_NOT_MATCHES);
  // The alg value SHOULD be the default of RS256. It MAY also be ES256.
  // In addition to RS256, an SIOP according to this specification MUST support EdDSA and ES256K.
  // --> https://identity.foundation/did-siop/#generate-siop-request
  // Note: this library implements only ES256
  if (
    header.alg !== DidAuthKeyAlgorithm.ES256K &&
    header.alg !== DidAuthKeyAlgorithm.ES256KR
  )
    throw new Error(DidAuthErrors.NO_ALG_SUPPORTED_YET);

  // The Client MUST validate the signature of the ID Token according to JWS [JWS]
  // using the algorithm specified in the alg Header Parameter of the JOSE Header,
  // using the key in the sub_jwk Claim; the key is a bare key in JWK format (not an X.509 certificate value).
  // SIOP: Verify the id_token according to the verification method above.
  // Verifying that the id_token was signed by the key specified in the sub_jwk claim.
  if (!util.verifySignatureFromVerificationMethod(id_token, verificationMethod))
    return {
      signatureValidation: false,
    };
  // The Client MUST validate that the sub Claim value is the base64url encoded representation
  // of the thumbprint of the key in the sub_jwk Claim.
  if (
    util.getThumbprint((payload as DidAuthResponsePayload).sub_jwk) !==
    payload.sub
  )
    throw new Error(DidAuthErrors.JWK_THUMBPRINT_MISMATCH_SUB);
  // If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and
  // its value checked to verify that it is the same value as the one that was sent in the Authentication Request.
  if (payload.nonce !== opts.nonce)
    throw Error(DidAuthErrors.ERROR_VALIDATING_NONCE);
  // Additionally performs a complete token validation via vidVerifyJwt
  const validationResponse = await verifyDidAuth(id_token, opts);

  return {
    signatureValidation: validationResponse.signatureValidation,
    payload: payload as DidAuthResponsePayload,
  };
};

export {
  createUriRequest,
  createUriResponse,
  createDidAuthRequest,
  createDidAuthResponse,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
};
