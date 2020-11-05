# Validated ID DID SIOP Auth Library

> This is a ValidatedID version of did-auth protocol to authenticate a user and a Relaying Party using vid DIDs.

The current DID Auth implementation follows [DID SIOP Auth](https://identity.foundation/did-siop/), which uses two JSON Web Tokens (JWT) signed by both two parties DID keys in a double challenge-response authentication. Is is also supported the protocol to exchange Verifiable Credentials as part of the ID token response.

Current version supports only `ES256k` algorithm (the EC secp256k1).

## Table of Contents

1. [Installation](#Installation)
2. [Authentication Flow](#Authentication-Flow)
3. [Usage](#Usage)
4. [Verifiable Credential Exchange Flow](#Verifiable-Credential-Exchange-Flow)
5. [Library Test](#Library-Test)

## Installation

```bash
npm install @validatedid/did-auth
```

or if you use `yarn`

```bash
yarn add @validatedid/did-auth
```

## Authentication Flow

The DID Auth flow has the following steps:

- An entity with a valid `did:vid` already generated wants to authenticate to a Relying Party (RP). For instance, by clicking on a `Login` button in RP's webpage.
- RP will use this library to create a DidAuthRequestCall URI Request calling `VidDidAuth.createUriRequest` with this payload:

```javascript
const didAuthRequestCall: DidAuthRequestCall = {
  requestUri: "https://app.example.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV", // Endpoint where the RP will store the token so the entity can access to it later on
  redirectUri: "https://app.example.net/demo/spanish-university", // Redirect URI after successful authentication
  signatureUri: "https://api.vidchain.net/wallet/v1/signatures", // VID wallet endpoint to create a signature
  authZToken: RPAuthZToken, // RP Access token received after calling VID wallet sessions endpoint
};

const { uri, nonce } = await VidDidAuth.createUriRequest(didAuthRequestCall);

console.log(uri);
// openid://?response_type=id_token&client_id=http://localhost:8080/demo/spanish-university&scope=openid did_authn&requestUri=https://dev.vidchain.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV
console.log(nonce);
// 5dedb59f-cc0d-4a7d-af20-ae05eea6b9e3
```

- RP receives an Open ID URI and nonce as a result:

<!-- prettier-ignore-start -->
```html
openid://?scope=openid%20did_authn&response_type=id_token&client_id=<redirectUri>&requestUri=<requestUri>
```
<!-- prettier-ignore-end -->

> _Note 1_: RP needs to store embbeded jwt in requestUri endpoint so the entity can retrieve it. For example, when a user scans this information from QR code using a wallet.
>
> _Note 2_: RP needs to store `nonce`, found inside the Request token to be used on the response validation process.

- RP sends the Uri Request to the SIOP client either via a QR code or deeplink:
<!-- prettier-ignore -->

<!-- prettier-ignore-start -->
```html
https://app.example.net/demo/wallet?did-auth=openid://?scope=openid%20did_authn&response_type=id_token&client_id=<redirectUri>&requestUri=<requestUri>
```
<!-- prettier-ignore-end -->

- SIOP client wallet parses the received a DID Auth Request URI to obtain `client_id` and `requestUri` URL parameters:

```javascript
import { parse } from "querystring";

const data = parse(uri);
const redirectUri = data.client_id;
const { requestUri } = data;
const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS;
const RPC_PROVIDER = process.env.DID_PROVIDER_RPC_URL;
```

- User needs to do a GET REST API call to `redirectUri` to receive the Jwt. This is out of scope of this library.

```javascript
// example of request JWT
console.log(didAuthRequestJwt);
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgwMTA2YTJlOTg1YjFFMURlOUI1ZGRiNGFGNmRDOWU5MjhGNGU5OUQwI2tleS0xIn0.eyJpYXQiOjE2MDQ1NTQzODcsImV4cCI6MTYwNDU1NDY4NywiaXNzIjoiZGlkOnZpZDoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAiLCJzY29wZSI6Im9wZW5pZCBkaWRfYXV0aG4iLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJjbGllbnRfaWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6IjVkZWRiNTlmLWNjMGQtNGE3ZC1hZjIwLWFlMDVlZWE2YjllMyJ9.Qcl96GdW3ci6aeqRA0lc0gbeFDJkE7yQyJfownGqqOfhsr7benjLuOfEeie8GdXZE_SXLhlvW03qp9feuRooywA

// Header
{
  "alg": "ES256K-R",
  "typ": "JWT",
  "kid": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1"
}
// Payload
{
  "iat": 1604554387,
  "exp": 1604554687,
  "iss": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
  "scope": "openid did_authn",
  "response_type": "id_token",
  "client_id": "http://localhost:8080/demo/spanish-university",
  "nonce": "5dedb59f-cc0d-4a7d-af20-ae05eea6b9e3"
}
```

- Once the user has the JWT, then the library is again used on this side to verify the token and create the Response token:

```javascript
// VERIFY DID-AUTH REQUEST
const requestPayload: DidAuthRequestPayload = await vidDidAuth.verifyDidAuthRequest(
  didAuthRequestJwt,
  RPC_ADDRESS,
  RPC_PROVIDER
);
```

- After a successful validation, user creates a DID Auth Response JWT token calling `vidDidAuth.createDidAuthResponse`, reusing the Request `nonce`.

```javascript
// CREATE A DID-AUTH RESPONSE
const didAuthResponseCall: DidAuthResponseCall = {
  hexPrivatekey: userPrivateKey, // private key managed by the user. Should be passed in hexadecimal format
  did: "did:vid:0x416e6e6162656c2e4c65652e452d412d506f652e", // User DID
  nonce: requestPayload.nonce, // same nonce received as a Request Payload after verifying it
  redirectUri, // parsed URI from the DID Auth Request payload
};
const didAuthResponseJwt = await vidDidAuth.createDidAuthResponse(
  didAuthResponseCall
);

console.log(didAuthResponseJwt)
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgxRjdlNTk2NDA1MjU2ZDM1MmQ1RDUwQ2Y1ZDk5Q0RBQjQyRjVFOGExI2tleS0xIn0.eyJpYXQiOjE2MDQ1NTQzODgsImV4cCI6MTYwNDU1NDY4OCwiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZSIsInN1YiI6InVtUFdwV0hVUjFhbnNwWHVHMlNNcXRIekxEeWN1VnFMYWJRRUNvYkNMcmMiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6IjVkZWRiNTlmLWNjMGQtNGE3ZC1hZjIwLWFlMDVlZWE2YjllMyIsInN1Yl9qd2siOnsia2lkIjoiZGlkOnZpZDoweDFGN2U1OTY0MDUyNTZkMzUyZDVENTBDZjVkOTlDREFCNDJGNUU4YTEja2V5LTEiLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiI3NzNjMGY3YjRjMjFmOWYxMzI4NzI5NGVlY2YwM2JkZjI0N2QwNDIxNjk5ZDhmYjc0ZTk0MWUwMTZiOWYyMjc4IiwieSI6IjZkMDkyMTFlZmQxZDZhZTYyOTE4MDU2YjhiNGY0MWI3MGUwN2IwMTU5Zjk3OTk3N2JjNzExZDBkZDk2OGIxMjYifX0.t2CO_G9KfYm6KF3I63bowzxERxENeI3U124d_SYqEj0h7MMconBt4ifYgROyCb4umMhZD2ivCcrMKluD0KsBYAE

// Header
{
  "alg": "ES256K-R",
  "typ": "JWT",
  "kid": "did:vid:0x1F7e596405256d352d5D50Cf5d99CDAB42F5E8a1#key-1"
}
// Payload
{
  "iat": 1604554388,
  "exp": 1604554688,
  "iss": "https://self-issued.me",
  "sub": "umPWpWHUR1anspXuG2SMqtHzLDycuVqLabQECobCLrc",
  "aud": "http://localhost:8080/demo/spanish-university",
  "nonce": "5dedb59f-cc0d-4a7d-af20-ae05eea6b9e3",
  "sub_jwk": {
    "kid": "did:vid:0x1F7e596405256d352d5D50Cf5d99CDAB42F5E8a1#key-1",
    "kty": "EC",
    "crv": "secp256k1",
    "x": "773c0f7b4c21f9f13287294eecf03bdf247d0421699d8fb74e941e016b9f2278",
    "y": "6d09211efd1d6ae62918056b8b4f41b70e07b0159f979977bc711d0dd968b126"
  }
}
```

- User does a POST REST API call to the RP `redirectUri` URI passing the Response token as a parameter:

<!-- prettier-ignore-start -->
```html
https://app.example.net/demo/spanish-university?response=<Signed JWT Response Object>
```
<!-- prettier-ignore-end -->

- RP verifies the DID Auth Response token calling `vidDidAuth.verifyDidAuthResponse` passing the stored nonce:

```javascript
const response = await vidDidAuth.verifyDidAuthResponse(
  didAuthResponseJwt, // DID Auth Response token to be validate
  "https://api.vidchain.net/wallet/signature-validations", // VIDchain wallet endpoint to validate a signature
  RPAuthZToken, // RP Access token received after calling VIDchain wallet sessions endpoint,
  nonce // RP stored nonce
);
```

- Response object contains a JSON struct with `signatureValidation` set to `true`:

```json
{
  "signatureValidation": true
}
```

- After a successful validation, RP and user are already authenticated, and RP shows the corresponding web page

## Usage

### Prerequisites

It is assumed that either the user and the Relying Party (RP) have an did:vid and can use their private keys to sign a given payload.

For instance:

```js
// User DID
const userDid = "did:vid:0x1F7e596405256d352d5D50Cf5d99CDAB42F5E8a1";
// Relying Party DID
const enterpriseDid = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
```

### Creating VID DID-Auth Request URI

Creates a DidAuth Request URI with a JWT signed with the RP DID key, using wallet backend endpoint URI given as a parameter `signatureUri` with an authorization token `authZToken`.

```js
import { DidAuthRequestCall, vidDidAuth } from "@validatedid/did-auth";

const didAuthRequestCall: DidAuthRequestCall = {
  redirectUri: "https://localhost:8080/demo/spanish-university",
  signatureUri: "http://api.vidchain.net/api/v1/signatures",
  authZToken: enterpriseAuthZToken,
};

const { uri, nonce } = await vidDidAuth.createUriRequest(didAuthRequestCall);
console.log(uri);
// openid://?response_type=id_token&client_id=http://localhost:8080/demo/spanish-university&scope=openid did_authn&requestUri=https://dev.vidchain.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV
console.log(nonce);
// 5dedb59f-cc0d-4a7d-af20-ae05eea6b9e3
```

### Verifying VID DID-Auth Request

Pass in a DID Auth Request JWT to verify the token:

```js
import { DidAuthRequestPayload, vidDidAuth } from "@validatedid/did-auth";

const payload: DidAuthRequestPayload = await vidDidAuth.verifyDidAuthRequest(
  didAuthJwt
);

console.log(payload);
// {
//   "iat": 1604554387,
//   "exp": 1604554687,
//   "iss": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
//   "scope": "openid did_authn",
//   "response_type": "id_token",
//   "client_id": "http://localhost:8080/demo/spanish-university",
//   "nonce": "5dedb59f-cc0d-4a7d-af20-ae05eea6b9e3"
// }
```

### Creating VID DID-Auth Response

Creates a DID Auth Response JWT signed with the user DID key, passed directly as a hexadecimal format.

```js
import { DidAuthResponseCall, vidDidAuth } from "@validatedid/did-auth";

const didAuthResponseCall: DidAuthResponseCall = {
  hexPrivatekey: getHexPrivateKey(testKeyUser.key),
  did: testKeyUser.did,
  nonce: requestPayload.nonce,
  redirectUri,
};
const didAuthResponseJwt = await vidDidAuth.createDidAuthResponse(
  didAuthResponseCall
);

console.log(didAuthResponseJwt);
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgxRjdlNTk2NDA1MjU2ZDM1MmQ1RDUwQ2Y1ZDk5Q0RBQjQyRjVFOGExI2tleS0xIn0.eyJpYXQiOjE2MDQ1NTQzODgsImV4cCI6MTYwNDU1NDY4OCwiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZSIsInN1YiI6InVtUFdwV0hVUjFhbnNwWHVHMlNNcXRIekxEeWN1VnFMYWJRRUNvYkNMcmMiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6IjVkZWRiNTlmLWNjMGQtNGE3ZC1hZjIwLWFlMDVlZWE2YjllMyIsInN1Yl9qd2siOnsia2lkIjoiZGlkOnZpZDoweDFGN2U1OTY0MDUyNTZkMzUyZDVENTBDZjVkOTlDREFCNDJGNUU4YTEja2V5LTEiLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiI3NzNjMGY3YjRjMjFmOWYxMzI4NzI5NGVlY2YwM2JkZjI0N2QwNDIxNjk5ZDhmYjc0ZTk0MWUwMTZiOWYyMjc4IiwieSI6IjZkMDkyMTFlZmQxZDZhZTYyOTE4MDU2YjhiNGY0MWI3MGUwN2IwMTU5Zjk3OTk3N2JjNzExZDBkZDk2OGIxMjYifX0.t2CO_G9KfYm6KF3I63bowzxERxENeI3U124d_SYqEj0h7MMconBt4ifYgROyCb4umMhZD2ivCcrMKluD0KsBYAE
```

### Verifying VID DID-Auth Response

Pass in a DID Auth Response JWT to verify the token:

> Note: Response code is 204. So, no response data is returned.

```js
import { DidAuthResponsePayload, vidDidAuth } from "@validatedid/did-auth";

const response = await vidDidAuth.verifyDidAuthResponse(didAuthJwt);
```

## Verifiable Credential Exchange Flow

Library supports the Credential Exchange Flow via the claims parameter OIDC spec.

Claims follows the [OIDC Core schema](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter), adding a top-level vc property as a sibling to (and following the schema of) id_token and userinfo. Requesting claims within the vc set indicates that the requesting party would like to receive (if essential is false), or requires (if true) a specific set of verifiable credential types within the .vp.verifiableCredential array of the SIOP Response. Specific [VC types](https://www.w3.org/TR/vc-data-model/#types) are identified using the VC type's full URI.

> Note: When providing claims in this manner, the SIOP Response acts as a W3C Verifiable Presentation; requested claims are provided in the Response by populating the array of Verifiable Credentials within the Presentation.

### Example of a claims request

Requesting a mandatory `VerifiableIdCredential`

```js
{
  "vc": {
    "VerifiableIdCredential": { essential: true },
  },
}
```

Requesting two mandatories Credentials: `VerifiableIdCredential` and `VidOnboardingCredential`

```js
{
  "vc": {
    "VerifiableIdCredential": { essential: true },
    "VidOnboardingCredential": { essential: true },
  },
}
```

### Example of a claims response

Response for a mandatory `VerifiableIdCredential`

```js
{
  "vp": {
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
        issuer: "did:vid:0x5208431C6EC2ec4097aeA7182bB92d018766498c",
        credentialSubject: {
          id: "did:vid:0x8707CCa835C961334D3F6450C6a61a0AD6592460",
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
            "did:vid:0x5208431C6EC2ec4097aeA7182bB92d018766498c#key-1",
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
        "did:vid:0x16048B83FAdaCdCB20198ABc45562Df1A3e289aF#key-1",
      jws:
        "eyJhbGciOiJFUzI1NksifQ.eyJzdWIiOiJFQlNJIDIwMTkifQ.oggE3ft3kJYPGGa9eBibpbjgeJXw4fLbVMouVoM2NfcDxsl_UUUIarsS1VpBoYEs7s9cBlc4uC0EbnJCHfVJIw",
    },
  },
}
```

### Creating a DID Auth Request with a Verifiable Credential Request

To request a specific credential on the DID Auth Request, you just need to add it to the library call.

```js
import { DidAuthRequestCall, vidDidAuth } from "@validatedid/did-auth";

const verifiableIdOidcClaim: OidcClaim = {
  vc: {
    VerifiableIdCredential: { essential: true },
  },
};

const didAuthRequestCall: DidAuthRequestCall = {
  redirectUri: "https://localhost:8080/demo/spanish-university",
  signatureUri: "http://api.vidchain.net/api/v1/signatures",
  authZToken: enterpriseAuthZToken,
  claims: verifiableIdOidcClaim,
};

const { uri, nonce, jwt } = await vidDidAuth.createUriRequest(
  didAuthRequestCall
);
console.log(jwt);
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgwMTA2YTJlOTg1YjFFMURlOUI1ZGRiNGFGNmRDOWU5MjhGNGU5OUQwI2tleS0xIn0.eyJpYXQiOjE2MDQ1NzE2ODYsImV4cCI6MTYwNDU3MTk4NiwiaXNzIjoiZGlkOnZpZDoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAiLCJzY29wZSI6Im9wZW5pZCBkaWRfYXV0aG4iLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJjbGllbnRfaWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6ImQyYWI5MDE4LTc4ZDctNGRhYy1hM2QwLTBlM2RiNjk2YTc0OSIsImNsYWltcyI6eyJ2YyI6eyJWZXJpZmlhYmxlSWRDcmVkZW50aWFsIjp7ImVzc2VudGlhbCI6dHJ1ZX19fX0.R5KolGcWhw0jPiCj_yd2bzrlc4R8wjkVGGBHa-bFEC4qwwl8L_WPRm07_xaYGkHCimpSuUzjWjeXw53jmS0dXgA

// Header
{
  "alg": "ES256K-R",
  "typ": "JWT",
  "kid": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1"
}
// Payload
{
  "iat": 1604571686,
  "exp": 1604571986,
  "iss": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
  "scope": "openid did_authn",
  "response_type": "id_token",
  "client_id": "http://localhost:8080/demo/spanish-university",
  "nonce": "d2ab9018-78d7-4dac-a3d0-0e3db696a749",
  "claims": {
    "vc": {
      "VerifiableIdCredential": {
        "essential": true
      }
    }
  }
}
```

### Creating a DID Auth Response with a Verifiable Presentation

To add a Verifiable Presentation to the DID Auth Response Object, you just need to add it to the `vp` parameter.

```js
import { DidAuthResponseCall, vidDidAuth } from "@validatedid/did-auth";

const didAuthResponseCall: DidAuthResponseCall = {
  hexPrivatekey: getHexPrivateKey(testKeyUser.key),
  did: testKeyUser.did,
  nonce: requestPayload.nonce,
  redirectUri,
  vp: verifiableIdPresentation,
};
const didAuthResponseJwt = await vidDidAuth.createDidAuthResponse(
  didAuthResponseCall
);

console.log(didAuthResponseJwt);
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgzMTJCQThDMWE1ZTA5RmNhNTUwZTFDNjkyYjNmMjcwZDNlMDcxMTA2I2tleS0xIn0.eyJpYXQiOjE2MDQ1NzE2ODgsImV4cCI6MTYwNDU3MTk4OCwiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZSIsInN1YiI6IkdXY19fdWJlTDRkdkRlNk5vTy1Yem1PWUE4LUZacmhuRU5SMHJaTld3ZkUiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6ImQyYWI5MDE4LTc4ZDctNGRhYy1hM2QwLTBlM2RiNjk2YTc0OSIsInN1Yl9qd2siOnsia2lkIjoiZGlkOnZpZDoweDMxMkJBOEMxYTVlMDlGY2E1NTBlMUM2OTJiM2YyNzBkM2UwNzExMDYja2V5LTEiLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiI3Yzk0NGI4YmFhNzRiMThhYjM5MzRiNjFjYzBlNGEzYjEwOTAwNGQ5MzA2MGExNDNkYmU0MjA1NDliNjZhYjRjIiwieSI6ImQxMmViYTBiNTA1NjJhYjI4ZTUwNzNiOWJjMDZlYWNjM2Q0YWZkMGU1ODU2NTE5NTllYWRiZjMwZjQwZGI2MTMifSwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6IlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2FwaS52aWRjaGFpbi5uZXQvY3JlZGVudGlhbHMvdmVyaWZpYWJsZUlkL3YxIl0sImlkIjoiaHR0cHM6Ly9hcGkudmlkY2hhaW4ubmV0L2FwaS92MS9zY2hlbWFzLzIzOTEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUlkQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6dmlkOjB4NTIwODQzMUM2RUMyZWM0MDk3YWVBNzE4MmJCOTJkMDE4NzY2NDk4YyIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOnZpZDoweDg3MDdDQ2E4MzVDOTYxMzM0RDNGNjQ1MEM2YTYxYTBBRDY1OTI0NjAiLCJmaXJzdE5hbWUiOiJFdmEiLCJsYXN0TmFtZSI6Ik1vbnJvZSIsImdlbmRlciI6IkZlbWFsZSIsImRhdGVPZkJpcnRoIjoiMTIvMTEvMTk3MCIsInBsYWNlT2ZCaXJ0aCI6Ik1hZHJpZCIsImN1cnJlbnRBZGRyZXNzIjoiQXJhZ28gMTc5IDRhIiwiY2l0eSI6IkJhcmNlbG9uYSIsInN0YXRlIjoiQ2F0YWx1w7FhIiwiemlwIjoiMDgwMTEifSwiaXNzdWFuY2VEYXRlIjoiMjAxOS0xMS0xN1QxNDowMDowMFoiLCJwcm9vZiI6eyJ0eXBlIjoiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5IiwiY3JlYXRlZCI6IjIwMTktMTEtMTdUMTQ6MDA6MDBaIiwicHJvb2ZQdXJwb3NlIjoiYXNzZXJ0aW9uTWV0aG9kIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOnZpZDoweDUyMDg0MzFDNkVDMmVjNDA5N2FlQTcxODJiQjkyZDAxODc2NjQ5OGMja2V5LTEiLCJqd3MiOiJleUpoYkdjaU9pSkZVekkxTmtzdFVpSXNJblI1Y0NJNklrcFhWQ0lzSW10cFpDSTZJbVJwWkRwMmFXUTZNSGd6WVdRelprWTRSVFZoUWpoRU5qa3pRekk0UW1SRU9VSTBOMlZrUkRGbU56UTBOVVk0WXpOR0kydGxlUzB4SW4wLmV5SnBZWFFpT2pFMU9URTNPVGsxTURRc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwzWXhJaXdpYUhSMGNITTZMeTloY0drdWRtbGtZMmhoYVc0dWJtVjBMMk55WldSbGJuUnBZV3h6TDNabGNtbG1hV0ZpYkdVdGFXUXZkakVpWFN3aWFXUWlPaUpvZEhSd2N6b3ZMMkZ3YVM1MmFXUmphR0ZwYmk1dVpYUXZZWEJwTDNZeEwzTmphR1Z0WVhNdk1qTTVNU0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSldaWEpwWm1saFlteGxTV1JEY21Wa1pXNTBhV0ZzSWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbWxrSWpvaVpHbGtPblpwWkRvd2VEUXlZamc1T0VVeU4wTTFObVUzWkRWQk1tUTBSVFkwTm1SQ01tUTBNVGhDUkRWRE1UY3dZelFpTENKbWFYSnpkRTVoYldVaU9pSkZkbUVpTENKc1lYTjBUbUZ0WlNJNklrMXZibkp2WlNJc0ltZGxibVJsY2lJNklrWmxiV0ZzWlNJc0ltUmhkR1ZQWmtKcGNuUm9Jam9pTVRJdk1URXZNVGszTUNJc0luQnNZV05sVDJaQ2FYSjBhQ0k2SWsxaFpISnBaQ0lzSW1OMWNuSmxiblJCWkdSeVpYTnpJam9pUVhKaFoyOGdNVGM1SURSaElpd2lZMmwwZVNJNklrSmhjbU5sYkc5dVlTSXNJbk4wWVhSbElqb2lRMkYwWVd4dmJtbGhJaXdpZW1sd0lqb2lNRGd3TVRFaWZTd2lhWE56ZFdWeUlqb2laR2xrT25acFpEb3dlRE5oWkRObVJqaEZOV0ZDT0VRMk9UTkRNamhDWkVRNVFqUTNaV1JFTVdZM05EUTFSamhqTTBZaWZTd2lhWE56SWpvaVpHbGtPblpwWkRvd2VETmhaRE5tUmpoRk5XRkNPRVEyT1RORE1qaENaRVE1UWpRM1pXUkVNV1kzTkRRMVJqaGpNMFlpZlEuQjdlNFpwOWpHTERYVFJHOElEMWowX0VWd29RbElfWER6U2FnS1dtRFItSU5qTVZTRkcxMTQyYXNDMXI1UmVkTnV1M1NSOFZJY0U5eXJiRHc5Y1J1RVFBIn19XSwicHJvb2YiOnsidHlwZSI6IkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsImNyZWF0ZWQiOiIyMDE5LTA2LTIyVDE0OjExOjQ0WiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDp2aWQ6MHgxNjA0OEI4M0ZBZGFDZENCMjAxOThBQmM0NTU2MkRmMUEzZTI4OWFGI2tleS0xIiwiandzIjoiZXlKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUp6ZFdJaU9pSkZRbE5KSURJd01Ua2lmUS5vZ2dFM2Z0M2tKWVBHR2E5ZUJpYnBiamdlSlh3NGZMYlZNb3VWb00yTmZjRHhzbF9VVVVJYXJzUzFWcEJvWUVzN3M5Y0JsYzR1QzBFYm5KQ0hmVkpJdyJ9fX0.s_Euyc49rNdIwB4E2Fexb6TH7HfUt7QFen7atoTv1I-1QYD-Q3uHJKeWsqNJDG5tiTRKCRxSGTy77vB6IWBLuQE

// Header
{
  "alg": "ES256K-R",
  "typ": "JWT",
  "kid": "did:vid:0x312BA8C1a5e09Fca550e1C692b3f270d3e071106#key-1"
}
// Payload
{
  "iat": 1604571688,
  "exp": 1604571988,
  "iss": "https://self-issued.me",
  "sub": "GWc__ubeL4dvDe6NoO-XzmOYA8-FZrhnENR0rZNWwfE",
  "aud": "http://localhost:8080/demo/spanish-university",
  "nonce": "d2ab9018-78d7-4dac-a3d0-0e3db696a749",
  "sub_jwk": {
    "kid": "did:vid:0x312BA8C1a5e09Fca550e1C692b3f270d3e071106#key-1",
    "kty": "EC",
    "crv": "secp256k1",
    "x": "7c944b8baa74b18ab3934b61cc0e4a3b109004d93060a143dbe420549b66ab4c",
    "y": "d12eba0b50562ab28e5073b9bc06eacc3d4afd0e585651959eadbf30f40db613"
  },
  "vp": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": "VerifiablePresentation",
    "verifiableCredential": [
      {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://api.vidchain.net/credentials/verifiableId/v1"
        ],
        "id": "https://api.vidchain.net/api/v1/schemas/2391",
        "type": [
          "VerifiableCredential",
          "VerifiableIdCredential"
        ],
        "issuer": "did:vid:0x5208431C6EC2ec4097aeA7182bB92d018766498c",
        "credentialSubject": {
          "id": "did:vid:0x8707CCa835C961334D3F6450C6a61a0AD6592460",
          "firstName": "Eva",
          "lastName": "Monroe",
          "gender": "Female",
          "dateOfBirth": "12/11/1970",
          "placeOfBirth": "Madrid",
          "currentAddress": "Arago 179 4a",
          "city": "Barcelona",
          "state": "Cataluña",
          "zip": "08011"
        },
        "issuanceDate": "2019-11-17T14:00:00Z",
        "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "created": "2019-11-17T14:00:00Z",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:vid:0x5208431C6EC2ec4097aeA7182bB92d018766498c#key-1",
          "jws": "eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgzYWQzZkY4RTVhQjhENjkzQzI4QmREOUI0N2VkRDFmNzQ0NUY4YzNGI2tleS0xIn0.eyJpYXQiOjE1OTE3OTk1MDQsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9hcGkudmlkY2hhaW4ubmV0L2NyZWRlbnRpYWxzL3ZlcmlmaWFibGUtaWQvdjEiXSwiaWQiOiJodHRwczovL2FwaS52aWRjaGFpbi5uZXQvYXBpL3YxL3NjaGVtYXMvMjM5MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlSWRDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOnZpZDoweDQyYjg5OEUyN0M1NmU3ZDVBMmQ0RTY0NmRCMmQ0MThCRDVDMTcwYzQiLCJmaXJzdE5hbWUiOiJFdmEiLCJsYXN0TmFtZSI6Ik1vbnJvZSIsImdlbmRlciI6IkZlbWFsZSIsImRhdGVPZkJpcnRoIjoiMTIvMTEvMTk3MCIsInBsYWNlT2ZCaXJ0aCI6Ik1hZHJpZCIsImN1cnJlbnRBZGRyZXNzIjoiQXJhZ28gMTc5IDRhIiwiY2l0eSI6IkJhcmNlbG9uYSIsInN0YXRlIjoiQ2F0YWxvbmlhIiwiemlwIjoiMDgwMTEifSwiaXNzdWVyIjoiZGlkOnZpZDoweDNhZDNmRjhFNWFCOEQ2OTNDMjhCZEQ5QjQ3ZWREMWY3NDQ1RjhjM0YifSwiaXNzIjoiZGlkOnZpZDoweDNhZDNmRjhFNWFCOEQ2OTNDMjhCZEQ5QjQ3ZWREMWY3NDQ1RjhjM0YifQ.B7e4Zp9jGLDXTRG8ID1j0_EVwoQlI_XDzSagKWmDR-INjMVSFG1142asC1r5RedNuu3SR8VIcE9yrbDw9cRuEQA"
        }
      }
    ],
    "proof": {
      "type": "EcdsaSecp256k1Signature2019",
      "created": "2019-06-22T14:11:44Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:vid:0x16048B83FAdaCdCB20198ABc45562Df1A3e289aF#key-1",
      "jws": "eyJhbGciOiJFUzI1NksifQ.eyJzdWIiOiJFQlNJIDIwMTkifQ.oggE3ft3kJYPGGa9eBibpbjgeJXw4fLbVMouVoM2NfcDxsl_UUUIarsS1VpBoYEs7s9cBlc4uC0EbnJCHfVJIw"
    }
  }
}
```

## Library Test

To run `e2e` you need to set these two environment variables either in a `.env` or passing as a parameter to `npm run test:e2e`:

- `DID_REGISTRY_SC_ADDRESS` as the current Smart Contract Address
- `WALLET_API_URL` as the base url for VIDchain API. i.e.: `http://api.vidchain.net`

You can use the `.env.example` from the repo and renamed it to `.env`.

```bash
# run tests
$ npm run test

# unit tests
$ npm run test:unit

# e2e tests
$ npm run test:e2e
```
