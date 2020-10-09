"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const did_jwt_1 = require("did-jwt");
const did_resolver_1 = require("did-resolver");
const crypto_1 = require("crypto");
const DIDAuth_1 = require("./DIDAuth");
const Errors_1 = __importDefault(require("./Errors"));
const Util_1 = require("./util/Util");
const VidDidResolver = require("@validated-id/vid-did-resolver");
class VidDidAuth {
    /**
     *
     * @param siopRequest
     */
    static async createUriRequest(didAuthRequestCall) {
        if (!didAuthRequestCall || !didAuthRequestCall.redirectUri)
            throw new Error(Errors_1.default.BAD_PARAMS);
        const { jwt, nonce } = await VidDidAuth.createDidAuthRequest(didAuthRequestCall);
        const responseUri = `openid://&scope=${DIDAuth_1.DIAUTHScope.OPENID_DIDAUTHN}?response_type=${DIDAuth_1.DIAUTHResponseType.ID_TOKEN}&client_id=${didAuthRequestCall.redirectUri}&requestUri=${didAuthRequestCall.requestUri}`;
        // returns a URI with Request JWT embedded
        return { uri: responseUri, nonce, jwt };
    }
    /**
     * Creates a DidAuth Request Object
     * @param didAuthRequestCall Request input data to build a signed DidAuth Request Token
     */
    static async createDidAuthRequest(didAuthRequestCall) {
        if (!didAuthRequestCall || !didAuthRequestCall.redirectUri)
            throw new Error(Errors_1.default.BAD_PARAMS);
        if (!didAuthRequestCall.signatureUri)
            throw new Error(Errors_1.default.KEY_SIGNATURE_URI_ERROR);
        if (!didAuthRequestCall.authZToken)
            throw new Error(Errors_1.default.AUTHZTOKEN_UNDEFINED);
        console.log("didAuthrequestPayload");
        const payload = this.createDidAuthRequestPayload(didAuthRequestCall);
        console.log("didAuthrequestPayload2");
        // signs payload calling the provided signatureUri
        const jwt = await this.signDidAuthExternal(payload, didAuthRequestCall.signatureUri, didAuthRequestCall.authZToken);
        return { jwt, nonce: payload.nonce };
    }
    /**
     * Verifies a DidAuth ID Request Token
     * @param didAuthJwt signed DidAuth Request Token
     * @param registry hexadecimal ddress where it is deployed the EBSI DID Smart Contract
     * @param rpcUrl URL for the EBSI DID Provider
     */
    static async verifyDidAuthRequest(didAuthJwt, registry, rpcUrl) {
        // as audience is set in payload as a DID, it is required to be set as options
        const options = {
            audience: this.getAudience(didAuthJwt),
            resolver: new did_resolver_1.Resolver(VidDidResolver.getResolver({
                rpcUrl,
                registry,
            })),
        };
        const verifiedJWT = await did_jwt_1.verifyJWT(didAuthJwt, options);
        if (!verifiedJWT || !verifiedJWT.payload)
            throw Error(Errors_1.default.ERROR_VERIFYING_SIGNATURE);
        return verifiedJWT.payload;
    }
    /**
     * Creates a DidAuth Response Object
     * @param input Response input data to build a signed DidAuth Response Token
     */
    static async createDidAuthResponse(didAuthResponseCall) {
        if (!didAuthResponseCall ||
            !didAuthResponseCall.hexPrivatekey ||
            !didAuthResponseCall.did ||
            !didAuthResponseCall.nonce ||
            !didAuthResponseCall.redirectUri)
            throw new Error(Errors_1.default.BAD_PARAMS);
        const payload = this.createDidAuthResponsePayload(didAuthResponseCall);
        // signs payload using internal libraries
        const jwt = await this.signDidAuthInternal(didAuthResponseCall.did, payload, didAuthResponseCall.hexPrivatekey);
        return jwt;
    }
    /**
     * Verifies a DidAuth ID Response Token
     * @param didAuthJwt igned DidAuth Response Token
     * @param nonce nonce value sent in the Authentication Request
     */
    static async verifyDidAuthResponse(didAuthJwt, verifyUri, authZToken, nonce) {
        const data = {
            jws: didAuthJwt,
        };
        try {
            const response = await Util_1.doPostCallWithToken(verifyUri, data, authZToken);
            if (!response || !response.status || response.status !== 204)
                throw Error(Errors_1.default.ERROR_VERIFYING_SIGNATURE);
        }
        catch (error) {
            throw Error(Errors_1.default.ERROR_VERIFYING_SIGNATURE);
        }
        const { payload } = did_jwt_1.decodeJWT(didAuthJwt);
        if (payload.nonce !== nonce)
            throw Error(Errors_1.default.ERROR_VALIDATING_NONCE);
        return {
            signatureValidation: true,
        };
    }
    static createDidAuthRequestPayload(input) {
        const { payload } = did_jwt_1.decodeJWT(input.authZToken);
        return {
            iss: payload.did,
            scope: DIDAuth_1.DIAUTHScope.OPENID_DIDAUTHN,
            response_type: DIDAuth_1.DIAUTHResponseType.ID_TOKEN,
            client_id: input.redirectUri,
            nonce: Util_1.getNonce(),
        };
    }
    static createDidAuthResponsePayload(input) {
        return {
            iss: DIDAuth_1.DIDAUTH_RESPONSE_ISS.SELF_ISSUE,
            sub: this.getThumbprint(input.hexPrivatekey),
            aud: input.redirectUri,
            nonce: input.nonce,
            sub_jwk: this.getJWK(input.hexPrivatekey, `${input.did}#key-1`),
        };
    }
    static async signDidAuthInternal(issuer, payload, hexPrivateKey) {
        // assign specific JWT header
        const header = {
            alg: DIDAuth_1.DIDAUTH_KEY_ALGO.ES256KR,
            typ: "JWT",
            kid: `${issuer}#key-1`,
        };
        const response = await did_jwt_1.createJWT(payload, {
            issuer: DIDAuth_1.DIDAUTH_RESPONSE_ISS.SELF_ISSUE,
            alg: DIDAuth_1.DIDAUTH_KEY_ALGO.ES256KR,
            signer: did_jwt_1.SimpleSigner(hexPrivateKey.replace("0x", "")),
            expiresIn: DIDAuth_1.expirationTime,
        }, header);
        return response;
    }
    static async signDidAuthExternal(payload, signatureUri, authZToken) {
        const data = {
            issuer: payload.iss,
            payload,
            type: "EcdsaSecp256k1Signature2019",
            expiresIn: DIDAuth_1.expirationTime,
        };
        const response = await Util_1.doPostCallWithToken(signatureUri, data, authZToken);
        if (!response ||
            !response.status ||
            (response.status !== 200 &&
                response.status !== 201) ||
            !response.data ||
            !response.data.jws)
            throw new Error(Errors_1.default.MALFORMED_SIGNATURE_RESPONSE);
        return response.data.jws;
    }
    static getJWK(hexPrivateKey, kid) {
        const { x, y } = Util_1.getECKeyfromHexPrivateKey(hexPrivateKey);
        return {
            kid,
            kty: DIDAuth_1.DIDAUTH_KEY_TYPE.EC,
            crv: DIDAuth_1.DIDAUTH_KEY_CURVE.SECP256k1,
            x,
            y,
        };
    }
    static getThumbprint(hexPrivateKey) {
        const jwk = this.getJWK(hexPrivateKey);
        const fields = {
            crv: jwk.crv,
            kty: jwk.kty,
            x: jwk.x,
            y: jwk.y,
        };
        const thumbprint = Util_1.base64urlEncodeBuffer(crypto_1.createHash("sha256").update(JSON.stringify(fields)).digest());
        return thumbprint;
    }
    static getAudience(jwt) {
        const { payload } = did_jwt_1.decodeJWT(jwt);
        if (!payload)
            throw new Error(Errors_1.default.NO_AUDIENCE);
        if (!payload.aud)
            return undefined;
        if (Array.isArray(payload.aud))
            throw new Error(Errors_1.default.INVALID_AUDIENCE);
        return payload.aud;
    }
}
exports.default = VidDidAuth;
//# sourceMappingURL=VidDIDAuth.js.map