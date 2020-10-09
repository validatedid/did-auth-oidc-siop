"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var DIDAUTH_ERRORS;
(function (DIDAUTH_ERRORS) {
    DIDAUTH_ERRORS["BAD_PARAMS"] = "Wrong parameters provided.";
    DIDAUTH_ERRORS["KEY_SIGNATURE_URI_ERROR"] = "Either Key or signature_uri MUST be provided.";
    DIDAUTH_ERRORS["AUTHZTOKEN_UNDEFINED"] = "AuthZToken MUST be defined.";
    DIDAUTH_ERRORS["MALFORMED_SIGNATURE_RESPONSE"] = "Response format is malformed";
    DIDAUTH_ERRORS["NO_ALG_SUPPORTED"] = "Algorithm not supported.";
    DIDAUTH_ERRORS["NO_KEY_CURVE_SUPPORTED"] = "Key Curve not supported.";
    DIDAUTH_ERRORS["ERROR_VERIFYING_SIGNATURE"] = "Error verifying the DID Auth Token signature.";
    DIDAUTH_ERRORS["ERROR_VALIDATING_NONCE"] = "Error validating nonce.";
    DIDAUTH_ERRORS["NO_AUDIENCE"] = "No audience found in JWT payload";
    DIDAUTH_ERRORS["INVALID_AUDIENCE"] = "Audience is invalid. Should be a string value.";
})(DIDAUTH_ERRORS || (DIDAUTH_ERRORS = {}));
exports.default = DIDAUTH_ERRORS;
//# sourceMappingURL=Errors.js.map