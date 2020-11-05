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

export interface Credential {
  "@context": string[];
  id: string;
  type: string[];
  credentialSubject: CredentialSubject;
  issuer: string;
  issuanceDate?: string;
  expirationDate?: string;
  credentialStatus?: CredentialStatus;
  [x: string]: unknown;
}

export interface VerifiableCredential extends Credential {
  issuer: string;
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

export interface OidcClaimRequest {
  essential?: boolean;
  value?: string | string[];
  values?: string[] | string[][];
}

export interface OidcClaim {
  vc?: null | OidcClaimRequest;
  [x: string]: unknown;
}
