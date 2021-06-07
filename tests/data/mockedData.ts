import { DIDDocument } from "did-resolver";
import { DidAuthTypes, JWTHeader, OidcSsi } from "../../src";

export const DIDAUTH_HEADER: JWTHeader = {
  typ: "JWT",
  alg: "ES256K",
  kid: "did:ethr:0x416e6e6162656c2e4c65652e452d412d506f652e#key1",
};

export const DIDAUTH_REQUEST_PAYLOAD: DidAuthTypes.DidAuthRequestPayload = {
  iss: "did:ethr:0x416e6e6162656c2e4c65652e452d412d506f652e", // DID of the RP (kid must point to a key in this DID Document)
  scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN, // MUST be "openid did_authn"
  response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN, // MUST be ID Token
  client_id: "http://app.example/demo", // Redirect URI after successful authentication
  nonce: "n-0S6_WzA2M", // MUST be a random string from a high-entropy source
  state: "af0ifjsldkj",
  registration: {
    // either using jwks_uri or jwks
    jwks_uri:
      "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
    id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256K,
  },
  exp: 1569937756, // Unix Timestamp; Date and time when the ID Token expires.
  iat: 1569934156,
};

export const DIDAUTH_RESPONSE_PAYLOAD: DidAuthTypes.DidAuthResponsePayload = {
  iss: DidAuthTypes.DidAuthResponseIss.SELF_ISSUE, // MUST be https://self-issued.me
  sub: "QS+5mH5GqVxuah94+D9wV97mMKZ6iMzW1op4B4s02Jk=", // Thumbprint of the sub_jwk
  aud: "http://app.example/demo", // MUST be client_id from the Request Object
  exp: 1569937756, // Unix Timestamp; Date and time when the ID Token expires.
  iat: 1569934156, // Unix Timestamp; Date and time when the Token was issued.
  nonce: "6a6b57a9d4e1a130b0edbe1ec4ae8823",
  sub_jwk: {
    crv: "secp256k1",
    kid: "did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111#keys-1",
    kty: "EC",
    x: "7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    y: "3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o",
  },
  did: "did:ethr:0x226e2e2223333c2e4c65652e452d412d50611111",
};

export const verifiableIdOidcClaim: OidcSsi.OidcClaim = {
  vc: {
    VerifiableIdCredential: { essential: true },
  },
};

export const verifiableIdPresentation: OidcSsi.VerifiablePresentation = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  type: "VerifiablePresentation",
  verifiableCredential: [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://api.vidchain.net/credentials/verifiableId/v1",
      ],
      id: "https://api.vidchain.net/api/v1/schemas/2391",
      type: ["VerifiableCredential", "VerifiableIdCredential"],
      issuer: "did:ethr:0x5208431C6EC2ec4097aeA7182bB92d018766498c",
      credentialSubject: {
        id: "did:ethr:0x8707CCa835C961334D3F6450C6a61a0AD6592460",
        firstName: "Eva",
        lastName: "Monroe",
        gender: "Female",
        dateOfBirth: "12/11/1970",
        placeOfBirth: "Madrid",
        currentAddress: "Arago 179 4a",
        city: "Barcelona",
        state: "Cataluña",
        zip: "08011",
      },
      issuanceDate: "2019-11-17T14:00:00Z",
      proof: {
        type: "EcdsaSecp256k1Signature2019",
        created: "2019-11-17T14:00:00Z",
        proofPurpose: "assertionMethod",
        verificationMethod:
          "did:ethr:0x5208431C6EC2ec4097aeA7182bB92d018766498c#keys-1",
        jws:
          "eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgzYWQzZkY4RTVhQjhENjkzQzI4QmREOUI0N2VkRDFmNzQ0NUY4YzNGI2tleS0xIn0.eyJpYXQiOjE1OTE3OTk1MDQsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9hcGkudmlkY2hhaW4ubmV0L2NyZWRlbnRpYWxzL3ZlcmlmaWFibGUtaWQvdjEiXSwiaWQiOiJodHRwczovL2FwaS52aWRjaGFpbi5uZXQvYXBpL3YxL3NjaGVtYXMvMjM5MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlSWRDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOnZpZDoweDQyYjg5OEUyN0M1NmU3ZDVBMmQ0RTY0NmRCMmQ0MThCRDVDMTcwYzQiLCJmaXJzdE5hbWUiOiJFdmEiLCJsYXN0TmFtZSI6Ik1vbnJvZSIsImdlbmRlciI6IkZlbWFsZSIsImRhdGVPZkJpcnRoIjoiMTIvMTEvMTk3MCIsInBsYWNlT2ZCaXJ0aCI6Ik1hZHJpZCIsImN1cnJlbnRBZGRyZXNzIjoiQXJhZ28gMTc5IDRhIiwiY2l0eSI6IkJhcmNlbG9uYSIsInN0YXRlIjoiQ2F0YWxvbmlhIiwiemlwIjoiMDgwMTEifSwiaXNzdWVyIjoiZGlkOnZpZDoweDNhZDNmRjhFNWFCOEQ2OTNDMjhCZEQ5QjQ3ZWREMWY3NDQ1RjhjM0YifSwiaXNzIjoiZGlkOnZpZDoweDNhZDNmRjhFNWFCOEQ2OTNDMjhCZEQ5QjQ3ZWREMWY3NDQ1RjhjM0YifQ.B7e4Zp9jGLDXTRG8ID1j0_EVwoQlI_XDzSagKWmDR-INjMVSFG1142asC1r5RedNuu3SR8VIcE9yrbDw9cRuEQA",
      },
    },
  ],
  proof: {
    type: "EcdsaSecp256k1Signature2019",
    created: "2019-06-22T14:11:44Z",
    proofPurpose: "assertionMethod",
    verificationMethod:
      "did:ethr:0x16048B83FAdaCdCB20198ABc45562Df1A3e289aF#keys-1",
    jws:
      "eyJhbGciOiJFUzI1NksifQ.eyJzdWIiOiJFQlNJIDIwMTkifQ.oggE3ft3kJYPGGa9eBibpbjgeJXw4fLbVMouVoM2NfcDxsl_UUUIarsS1VpBoYEs7s9cBlc4uC0EbnJCHfVJIw",
  },
};

export const DIDAUTH_REQUEST_PAYLOAD_CLAIMS = {
  ...DIDAUTH_REQUEST_PAYLOAD,
  claims: verifiableIdOidcClaim,
};

export const DIDAUTH_RESPONSE_PAYLOAD_VP = {
  ...DIDAUTH_RESPONSE_PAYLOAD,
  vp: verifiableIdPresentation,
};

export const DID_DOCUMENT_PUBKEY_B58: DIDDocument = {
  "@context": "https://w3id.org/did/v1",
  id: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C",
  controller: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C",
  authentication: ["did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C#key-1"],
  verificationMethod: [
    {
      id: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C#key-1",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:ethr:0xE3f80bcbb360F04865AfA795B7507d384154216C",
      publicKeyBase58:
        "PSPfR29Snu5yxJcLHf2t6SyJ9mttet19ECkDHr4HY3FD5YC8ZenjvspPSAGSpaQ8B8kXADV97WSd7JqaNAUTn8YG",
    },
  ],
};

export const DID_DOCUMENT_PUBKEY_JWK: DIDDocument = {
  "@context": "https://w3id.org/did/v1",
  id: "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513",
  controller: "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513",
  authentication: [
    "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513#JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
  ],
  verificationMethod: [
    {
      id:
        "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513#JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:ethr:0x96e9A346905a8F8D5ee0e6BA5D13456965e74513",
      publicKeyJwk: {
        kty: "EC",
        crv: "secp256k1",
        x: "62451c7a3e0c6e2276960834b79ae491ba0a366cd6a1dd814571212ffaeaaf5a",
        y: "1ede3d754090437db67eca78c1659498c9cf275d2becc19cdc8f1ef76b9d8159",
        kid: "JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
      },
    },
  ],
};
