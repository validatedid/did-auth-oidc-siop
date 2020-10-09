"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getECKeyfromHexPrivateKey = exports.base64urlEncodeBuffer = exports.doPostCallWithToken = exports.getHexPrivateKey = exports.getDIDFromKey = exports.getNonce = void 0;
const uuid_1 = require("uuid");
const axios_1 = __importDefault(require("axios"));
const ethers_1 = require("ethers");
const elliptic_1 = require("elliptic");
function getNonce() {
    return uuid_1.v4();
}
exports.getNonce = getNonce;
function toHex(data) {
    return Buffer.from(data, "base64").toString("hex");
}
function getEthWallet(key) {
    return new ethers_1.ethers.Wallet(toHex(key.d));
}
function getHexPrivateKey(key) {
    return getEthWallet(key).privateKey;
}
exports.getHexPrivateKey = getHexPrivateKey;
function getEthAddress(key) {
    return getEthWallet(key).address;
}
function getDIDFromKey(key) {
    return `did:ebsi:${getEthAddress(key)}`;
}
exports.getDIDFromKey = getDIDFromKey;
const fromBase64 = (base64) => {
    return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};
const base64urlEncodeBuffer = (buf) => {
    return fromBase64(buf.toString("base64"));
};
exports.base64urlEncodeBuffer = base64urlEncodeBuffer;
function getECKeyfromHexPrivateKey(hexPrivateKey) {
    const ec = new elliptic_1.ec("secp256k1");
    const privKey = ec.keyFromPrivate(hexPrivateKey);
    const pubPoint = privKey.getPublic();
    return {
        x: pubPoint.getX().toString("hex"),
        y: pubPoint.getY().toString("hex"),
    };
}
exports.getECKeyfromHexPrivateKey = getECKeyfromHexPrivateKey;
async function doPostCallWithToken(url, data, token) {
    const config = {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    };
    const response = await axios_1.default.post(url, data, config);
    return response;
}
exports.doPostCallWithToken = doPostCallWithToken;
//# sourceMappingURL=Util.js.map