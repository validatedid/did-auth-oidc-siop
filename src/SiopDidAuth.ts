import { decodeJWT } from "did-jwt";
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

  const didAuthResponsePayload: DidAuthResponsePayload = createDidAuthResponsePayload(
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
const verifyDidAuthRequest = verifyDidAuth;

/**
 * Verifies an id_token result of a DID Auth Response
 * @param id_token signed didAuth Response Token
 * @param opts Verify options to use internal or external verification method
 */
const verifyDidAuthResponse = async (
  id_token: string,
  opts: DidAuthVerifyOpts
): Promise<DidAuthValidationResponse> => {
  if (!id_token || !opts || !opts.verificationType || !opts.nonce)
    throw new Error(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  const validationResponse = await verifyDidAuth(id_token, opts);

  const { payload } = decodeJWT(id_token);
  if (payload.nonce !== opts.nonce)
    throw Error(DidAuthErrors.ERROR_VALIDATING_NONCE);

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
