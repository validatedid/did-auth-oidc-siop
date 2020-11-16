enum DidAuthErrors {
  BAD_PARAMS = "Wrong parameters provided.",
  MALFORMED_SIGNATURE_RESPONSE = "Response format is malformed",
  NO_ALG_SUPPORTED = "Algorithm not supported.",
  NO_KEY_CURVE_SUPPORTED = "Key Curve not supported.",
  ERROR_VERIFYING_SIGNATURE = "Error verifying the DID Auth Token signature.",
  ERROR_VALIDATING_NONCE = "Error validating nonce.",
  NO_AUDIENCE = "No audience found in JWT payload",
  INVALID_AUDIENCE = "Audience is invalid. Should be a string value.",
  REQUEST_OBJECT_TYPE_NOT_SET = "Request object type is not set.",
  NO_REFERENCE_URI = "referenceUri must be defined when REFERENCE option is used",
  BAD_SIGNATURE_PARAMS = "Signature parameters should be internal signature with hexPrivateKey, did, and an optional kid, or external signature parameters with signatureUri, did, and optionals parameters authZToken, hexPublicKey, and kid",
  REGISTRATION_OBJECT_TYPE_NOT_SET = "Registration object type is not set.",
  DIDAUTH_REQUEST_PAYLOAD_NOT_CREATED = "DidAuthRequestPayload not created",
  VERIFY_BAD_PARAMETERS = "Verify bad parameters",
  VERIFICATION_METHOD_NOT_SUPPORTED = "Verification method not supported",
}

export default DidAuthErrors;
