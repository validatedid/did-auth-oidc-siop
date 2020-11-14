import { JWTClaims } from "./JWT";
import { JWKECKey } from "./JWK";
import { OidcClaim, VerifiablePresentation } from "./oidcSsi";

export enum DidAuthKeyType {
  EC = "EC", // default
  RSA = "RSA",
}

export enum DidAuthKeyCurve {
  SECP256k1 = "secp256k1", // default
  ED25519 = "ed25519",
}

export enum DidAuthKeyAlgorithm {
  ES256KR = "ES256K-R", // default
  ES256K = "ES256K",
  RS256 = "RS256",
  EDDSA = "EdDSA",
}

export enum EncSymmetricAlgorithmCode {
  XC20P = "XC20P", // default
}

export enum EncSymmetricAlgorithm {
  XCHACHA20 = "XChaCha20", // default
}

export enum EncSymmetricAuthenticationTag {
  POLY1305 = "Poly1305", // default
}

export enum EncKeyCurve {
  X25519 = "X25519", // default
}

export enum EncKeyAlgorithm {
  ECDH_ES = "ECDH-ES", // default
}

export enum DidAuthScope {
  OPENID_DIDAUTHN = "openid did_authn",
}

export enum DidAuthResponseType {
  ID_TOKEN = "id_token",
}

export enum DidAuthResponseMode {
  FRAGMENT = "fragment", // default
  FORM_POST = "form_post",
  QUERY = "query",
}

export enum DidAuthResponseContext {
  RP = "rp", // default
  WALLET = "wallet",
}

export enum DidAuthResponseIss {
  SELF_ISSUE = "https://self-issued.me",
}

export interface RegistrationJwksUri {
  jwks_uri: string;
  id_token_signed_response_alg: DidAuthKeyAlgorithm;
}

export interface RegistrationJwks {
  jwks: JWKECKey;
}

export const expirationTime = 5 * 60; // token expires in 5 minutes (in seconds)

export enum ObjectPassedBy {
  REFERENCE = "REFERENCE",
  VALUE = "VALUE",
}

export type RequestObjectBy = {
  type: ObjectPassedBy.REFERENCE | ObjectPassedBy.VALUE;
  referenceUri?: string; // MUST be set when options is REFERENCE
};

export interface InternalSignature {
  hexPrivateKey: string; // hex private key Only secp256k1 format
  did: string;
  kid?: string; // Optional: key identifier. default did#key-1
}

export interface ExternalSignature {
  signatureUri: string; // url to call to generate a signature
  did: string;
  authZToken?: string; // Optional: bearer token to use to the call
  hexPublicKey?: string; // Optional: hex encoded public key to compute JWK key, if not possible from DID Document
  kid?: string; // Optional: key identifier. default did#key-1
}

export interface RegistrationType extends RequestObjectBy {
  id_token_encrypted_response_alg?: EncKeyAlgorithm;
  id_token_encrypted_response_enc?: EncSymmetricAlgorithmCode;
}

export interface DidAuthRequestOpts {
  oidpUri: string;
  redirectUri: string;
  requestObjectBy: RequestObjectBy;
  signatureType: InternalSignature | ExternalSignature;
  registrationType: RegistrationType;
  responseMode?: DidAuthResponseMode;
  responseContext?: DidAuthResponseContext;
  claims?: OidcClaim;
  keySigningAlgorithm?: DidAuthKeyAlgorithm;
  nonce?: string;
  state?: string;
}

export interface DidAuthResponseOpts {
  redirectUri: string;
  signatureType: InternalSignature | ExternalSignature;
  nonce: string;
  state: string;
  registrationType: RegistrationType;
  responseMode?: DidAuthResponseMode;
  did: string;
  vp?: VerifiablePresentation;
}

export interface InternalVerification {
  registry: string;
  rpcUrl: string;
}

export interface ExternalVerification {
  verifyUri: string; // url to call to verify the id_token signature
  authZToken?: string; // Optional: bearer token to use to the call
}

export interface DidAuthVerifyOpts {
  verificationType: InternalVerification | ExternalVerification;
  nonce?: string;
}

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

export interface DidAuthValidationResponse {
  signatureValidation: boolean;
  payload?: DidAuthRequestPayload | DidAuthResponsePayload;
}

export interface SignatureResponse {
  jws: string;
}

export enum UrlEncodingFormat {
  FORM_URL_ENCODED = "application/x-www-form-urlencoded",
}

export type UriDidAuth = {
  urlEncoded: string;
  encoding: UrlEncodingFormat;
};

export interface UriResponse extends UriDidAuth {
  response_mode: DidAuthResponseMode;
  bodyEncoded?: string;
}

export interface UriRequest extends UriDidAuth {
  jwt?: string;
}

export interface DidAuthRequestResponse {
  jwt: string;
  nonce: string;
  state: string;
}
