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
  // Registered Claim names
  iss?: string; // (Issuer) Claim
  sub?: string; // (Subject) Claim
  aud?: string; // (Audience) Claim
  exp?: number; // (Expiration Time) Claim.
  nbf?: number; // (Not Before) Claim
  iat?: number; // (Issued At) Claim
  jti?: string; // (JWT ID) Claim
}

export interface EnterpriseAuthZToken extends JWTClaims {
  did: string;
  enterpriseName: string;
  nonce: string;
}
