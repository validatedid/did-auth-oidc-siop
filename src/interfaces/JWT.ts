import { DIDDocument } from "./oidcSsi";

export interface Resolvable {
  resolve: (did: string) => Promise<DIDDocument | null>;
}

export interface JWTVerifyOptions {
  auth?: boolean;
  audience?: string;
  callbackUrl?: string;
  resolver?: Resolvable | string;
}

export interface JWTHeader {
  typ: "JWT";
  alg: string;
  jwk?: string;
  jku?: string;
  kid?: string;
  [x: string]: unknown;
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

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string;
  iat?: number;
  nbf?: number;
  type?: string;
  exp?: number;
  rexp?: number;
  [x: string]: unknown;
}
export interface JWTDecoded {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
  data: string;
}
