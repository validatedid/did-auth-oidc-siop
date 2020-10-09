import { DIDDocument } from "did-resolver";
import { JWTClaims } from "./JWT";
import { JWKECKey } from "./util/JWK";
export declare enum DIDAUTH_KEY_TYPE {
    EC = "EC"
}
export declare enum DIDAUTH_KEY_CURVE {
    SECP256k1 = "secp256k1"
}
export declare enum DIDAUTH_KEY_ALGO {
    ES256KR = "ES256K-R",
    ES256K = "ES256K"
}
export declare enum DIAUTHScope {
    OPENID_DIDAUTHN = "openid did_authn"
}
export declare enum DIAUTHResponseType {
    ID_TOKEN = "id_token"
}
export declare enum DIDAUTH_RESPONSE_ISS {
    SELF_ISSUE = "https://self-issued.me"
}
export declare const expirationTime: number;
export interface DidAuthRequestPayload extends JWTClaims {
    iss: string;
    scope: DIAUTHScope;
    response_type: DIAUTHResponseType;
    client_id: string;
    nonce: string;
    did_doc?: DIDDocument;
}
export interface DidAuthResponsePayload extends JWTClaims {
    iss: DIDAUTH_RESPONSE_ISS.SELF_ISSUE;
    sub: string;
    aud: string;
    exp?: number;
    iat?: number;
    nonce: string;
    sub_jwk: JWKECKey;
}
export interface DidAuthRequestCall {
    redirectUri: string;
    requestUri: string;
    signatureUri: string;
    authZToken: string;
}
export interface DidAuthResponseCall {
    hexPrivatekey: string;
    did: string;
    nonce: string;
    redirectUri: string;
}
export interface DidAuthValidationResponse {
    signatureValidation: boolean;
}
//# sourceMappingURL=DIDAuth.d.ts.map