enum DIDAUTH_ERRORS {
  BAD_PARAMS = "Wrong parameters provided.",
  KEY_SIGNATURE_URI_ERROR = "Either Key or signature_uri MUST be provided.",
  AUTHZTOKEN_UNDEFINED = "AuthZToken MUST be defined.",
  MALFORMED_SIGNATURE_RESPONSE = "Response format is malformed",
  NO_ALG_SUPPORTED = "Algorithm not supported.",
  NO_KEY_CURVE_SUPPORTED = "Key Curve not supported.",
  ERROR_VERIFYING_SIGNATURE = "Error verifying the DID Auth Token signature.",
  ERROR_VALIDATING_NONCE = "Error validating nonce.",
  NO_AUDIENCE = "No audience found in JWT payload",
  INVALID_AUDIENCE = "Audience is invalid. Should be a string value.",
}

export default DIDAUTH_ERRORS;
