import { Resolver, DIDDocument } from "did-resolver";
export interface VerifiedJwt {
    payload: any;
    doc?: DIDDocument;
    issuer?: string;
    signer?: object;
    jwt: string;
}
export interface JWTVerifyOptions {
    auth?: boolean;
    audience?: string;
    callbackUrl?: string;
    resolver: Resolver;
}
export interface JWTHeader {
    typ: "JWT";
    alg: string;
    jwk?: string;
    jku?: string;
    kid?: string;
}
export interface JWTClaims {
    iss?: string;
    sub?: string;
    aud?: string;
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
}
export interface EnterpriseAuthZToken extends JWTClaims {
    did: string;
    enterpriseName: string;
    nonce: string;
}
//# sourceMappingURL=JWT.d.ts.map