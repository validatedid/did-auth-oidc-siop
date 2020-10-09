"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DIDAUTH_ERRORS = exports.VidDidAuth = void 0;
const VidDIDAuth_1 = __importDefault(require("./VidDIDAuth"));
exports.VidDidAuth = VidDIDAuth_1.default;
const Errors_1 = __importDefault(require("./Errors"));
exports.DIDAUTH_ERRORS = Errors_1.default;
var DIDAuth_1 = require("./DIDAuth");
Object.defineProperty(exports, "DIDAUTH_KEY_TYPE", { enumerable: true, get: function () { return DIDAuth_1.DIDAUTH_KEY_TYPE; } });
Object.defineProperty(exports, "DIDAUTH_KEY_CURVE", { enumerable: true, get: function () { return DIDAuth_1.DIDAUTH_KEY_CURVE; } });
Object.defineProperty(exports, "DIDAUTH_KEY_ALGO", { enumerable: true, get: function () { return DIDAuth_1.DIDAUTH_KEY_ALGO; } });
Object.defineProperty(exports, "DIAUTHScope", { enumerable: true, get: function () { return DIDAuth_1.DIAUTHScope; } });
Object.defineProperty(exports, "DIAUTHResponseType", { enumerable: true, get: function () { return DIDAuth_1.DIAUTHResponseType; } });
Object.defineProperty(exports, "DIDAUTH_RESPONSE_ISS", { enumerable: true, get: function () { return DIDAuth_1.DIDAUTH_RESPONSE_ISS; } });
var Util_1 = require("./util/Util");
Object.defineProperty(exports, "getHexPrivateKey", { enumerable: true, get: function () { return Util_1.getHexPrivateKey; } });
Object.defineProperty(exports, "getDIDFromKey", { enumerable: true, get: function () { return Util_1.getDIDFromKey; } });
Object.defineProperty(exports, "getNonce", { enumerable: true, get: function () { return Util_1.getNonce; } });
//# sourceMappingURL=index.js.map