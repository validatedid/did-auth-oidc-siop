import { JWK } from "jose";

export interface CredentialSubject {
  [x: string]: unknown;
}

export interface Proof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  jws: string;
  [x: string]: string;
}

export interface CredentialStatus {
  id: string;
  type: string;
}

export interface Issuer {
  id: string;
  name: string;
}

export interface Credential {
  "@context": string[];
  id: string;
  type: string[];
  credentialSubject: CredentialSubject;
  issuer: string | Issuer;
  issuanceDate?: string;
  expirationDate?: string;
  credentialStatus?: CredentialStatus;
  [x: string]: unknown;
}

export interface VerifiableCredential extends Credential {
  issuanceDate: string;
  proof: Proof;
}

export interface Presentation {
  "@context": string[];
  type: string;
  verifiableCredential: string[] | VerifiableCredential[];
}

export interface VerifiablePresentation extends Presentation {
  proof: Proof;
}

export interface OidcClaimJson {
  essential?: boolean;
  value?: string;
  values?: string[];
}

export interface OidcClaimRequest {
  [x: string]: null | OidcClaimJson;
}

export interface OidcClaim {
  vc?: OidcClaimRequest;
  [x: string]: unknown;
}
export interface DIDDocument {
  "@context": "https://w3id.org/did/v1";
  id: string;
  controller?: string;
  owner?: string;
  publicKey?: PublicKey[];
  authentication?: Authentication[];
  verificationMethod?: VerificationMethod[];
  service?: ServiceEndpoint[];
  created?: string;
  updated?: string;
  proof?: LinkedDataProof;
}

export interface PublicKey {
  id: string;
  type: string;
  controller: string;
  ethereumAddress?: string;
  publicKeyBase64?: string;
  publicKeyBase58?: string;
  publicKeyHex?: string;
  publicKeyPem?: string;
  publicKeyJwk?: JWK;
}
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyBase58?: string;
  publicKeyJwk?: JWK;
}

export interface Authentication {
  type: string;
  publicKey: string;
}
export interface LinkedDataProof {
  type: string;
  created: string;
  creator: string;
  nonce: string;
  signatureValue: string;
}
export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
  description?: string;
}
