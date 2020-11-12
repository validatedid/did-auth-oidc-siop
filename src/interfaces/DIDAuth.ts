import { JWTClaims } from "./JWT";
import { JWKECKey } from "./JWK";
import { OidcClaim, VerifiablePresentation } from "./oidcSsi";

export enum DidAuthKeyType {
  EC = "EC",
}

export enum DidAuthKeyCurve {
  SECP256k1 = "secp256k1",
}

export enum DidAuthKeyAlgo {
  ES256KR = "ES256K-R",
  ES256K = "ES256K",
}

export enum DidAuthScope {
  OPENID_DIDAUTHN = "openid did_authn",
}

export enum DidAuthResponseType {
  ID_TOKEN = "id_token",
}

export enum DidAuthResponseMode {
  FRAGMENT = "fragment",
  FORM_POST = "form_post",
  QUERY = "query",
}

export enum DidAuthResponseContext {
  RP = "rp",
  WALLET = "wallet",
}

export enum DidAuthResponseIss {
  SELF_ISSUE = "https://self-issued.me",
}

export interface RegistrationJwksUri {
  jwks_uri: string;
  id_token_signed_response_alg: DidAuthKeyAlgo;
}

export interface RegistrationJwks {
  jwks: JWKECKey;
}

export const expirationTime = 5 * 60; // token expires in 5 minutes (in seconds)

export interface DidAuthRequestPayload extends JWTClaims {
  iss: string;
  scope: DidAuthScope;
  registration: RegistrationJwksUri | RegistrationJwks;
  client_id: string;
  nonce: string;
  state: string;
  response_type: DidAuthResponseType;
  response_mode?: DidAuthResponseMode;
  response_context?: DidAuthResponseContext;
  claims?: OidcClaim;
}

export interface DidAuthResponsePayload extends JWTClaims {
  iss: DidAuthResponseIss.SELF_ISSUE;
  sub: string;
  aud: string;
  exp?: number;
  iat?: number;
  nonce: string;
  sub_jwk: JWKECKey;
  did: string;
  vp?: VerifiablePresentation;
}

export interface DidAuthRequestCall {
  redirectUri: string;
  signatureUri: string;
  authZToken: string;
  requestUri?: string;
  claims?: OidcClaim;
}

export interface DidAuthResponseCall {
  hexPrivatekey: string;
  did: string;
  nonce: string;
  redirectUri: string;
  vp?: VerifiablePresentation;
}

export interface DidAuthValidationResponse {
  signatureValidation: boolean;
}

export interface SignatureResponse {
  jws: string;
}
