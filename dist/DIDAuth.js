"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.expirationTime = exports.DIDAUTH_RESPONSE_ISS = exports.DIAUTHResponseType = exports.DIAUTHScope = exports.DIDAUTH_KEY_ALGO = exports.DIDAUTH_KEY_CURVE = exports.DIDAUTH_KEY_TYPE = void 0;
var DIDAUTH_KEY_TYPE;
(function (DIDAUTH_KEY_TYPE) {
    DIDAUTH_KEY_TYPE["EC"] = "EC";
})(DIDAUTH_KEY_TYPE = exports.DIDAUTH_KEY_TYPE || (exports.DIDAUTH_KEY_TYPE = {}));
var DIDAUTH_KEY_CURVE;
(function (DIDAUTH_KEY_CURVE) {
    DIDAUTH_KEY_CURVE["SECP256k1"] = "secp256k1";
})(DIDAUTH_KEY_CURVE = exports.DIDAUTH_KEY_CURVE || (exports.DIDAUTH_KEY_CURVE = {}));
var DIDAUTH_KEY_ALGO;
(function (DIDAUTH_KEY_ALGO) {
    DIDAUTH_KEY_ALGO["ES256KR"] = "ES256K-R";
    DIDAUTH_KEY_ALGO["ES256K"] = "ES256K";
})(DIDAUTH_KEY_ALGO = exports.DIDAUTH_KEY_ALGO || (exports.DIDAUTH_KEY_ALGO = {}));
var DIAUTHScope;
(function (DIAUTHScope) {
    DIAUTHScope["OPENID_DIDAUTHN"] = "openid did_authn";
})(DIAUTHScope = exports.DIAUTHScope || (exports.DIAUTHScope = {}));
var DIAUTHResponseType;
(function (DIAUTHResponseType) {
    DIAUTHResponseType["ID_TOKEN"] = "id_token";
})(DIAUTHResponseType = exports.DIAUTHResponseType || (exports.DIAUTHResponseType = {}));
var DIDAUTH_RESPONSE_ISS;
(function (DIDAUTH_RESPONSE_ISS) {
    DIDAUTH_RESPONSE_ISS["SELF_ISSUE"] = "https://self-issued.me";
})(DIDAUTH_RESPONSE_ISS = exports.DIDAUTH_RESPONSE_ISS || (exports.DIDAUTH_RESPONSE_ISS = {}));
exports.expirationTime = 5 * 60; // token expires in 5 minutes (in seconds)
//# sourceMappingURL=DIDAuth.js.map