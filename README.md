# Validated ID DID SIOP Auth Library

> This is a ValidatedID version of did-auth protocol to authenticate a user and a Relaying Party using vid DIDs.

The current DID Auth implementation follows [DID SIOP Auth](https://identity.foundation/did-siop/), which uses two JSON Web Tokens (JWT) signed by both two parties DID keys in a double challenge-response authentication. Is is also supported the protocol to exchange Verifiable Credentials as part of the ID token response.

Current version supports only `ES256k` algorithm (the EC secp256k1).

## Table of Contents

1. [Installation](#Installation)
2. [Authentication Flow](#Authentication-Flow)
3. [Usage](#Usage)
4. [Optional: Verifiable Credential Exchange Flow](#Optional:-Verifiable-Credential-Exchange-Flow)
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

## Optional: Verifiable Credential Exchange Flow

Library supports the Credential Exchange Flow via the claims parameter OIDC spec.

Claims follows the [OIDC Core schema](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter), adding a top-level vc property as a sibling to (and following the schema of) id_token and userinfo. Requesting claims within the vc set indicates that the requesting party would like to receive (if essential is false), or requires (if true) a specific set of verifiable credential types within the .vp.verifiableCredential array of the SIOP Response. Specific [VC types](https://www.w3.org/TR/vc-data-model/#types) are identified using the VC type's full URI.

> Note: When providing claims in this manner, the SIOP Response acts as a W3C Verifiable Presentation; requested claims are provided in the Response by populating the array of Verifiable Credentials within the Presentation.

### Example of a claims request

Requesting a mandatory `VerifiableIdCredential`

```js
{
  "vc": {
    "essential": true,
    "value": ["VerifiableCredential", "VerifiableIdCredential"],
  },
}
```

Requesting two mandatories Credentials: `VerifiableIdCredential` and `VidOnboardingCredential`

```js
{
  "vc": {
    "essential": true,
    "values": [
      ["VerifiableCredential", "VerifiableIdCredential"],
      ["VerifiableCredential", "VidOnboardingCredential"],
    ]
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
    essential: true,
    value: ["VerifiableCredential", "VerifiableIdCredential"],
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
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHgwMTA2YTJlOTg1YjFFMURlOUI1ZGRiNGFGNmRDOWU5MjhGNGU5OUQwI2tleS0xIn0.eyJpYXQiOjE2MDQ1NTY3MDAsImV4cCI6MTYwNDU1NzAwMCwiaXNzIjoiZGlkOnZpZDoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAiLCJzY29wZSI6Im9wZW5pZCBkaWRfYXV0aG4iLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJjbGllbnRfaWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6IjVhM2YzNzAxLWUyOTUtNDYzNS1iZWY1LTU1OWYxOTlhYmQwMyIsImNsYWltcyI6eyJ2YyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUlkQ3JlZGVudGlhbCJdfX19.DAQqw63Om4Eyro94BWnrXLafOV5kiXcNiqVGp7TqQK5DNdms0BpHDq3N6zzazdjfff7HwyK415m4SutmHdilcQE

// Header
{
  "alg": "ES256K-R",
  "typ": "JWT",
  "kid": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1"
}
// Payload
{
  "iat": 1604556700,
  "exp": 1604557000,
  "iss": "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
  "scope": "openid did_authn",
  "response_type": "id_token",
  "client_id": "http://localhost:8080/demo/spanish-university",
  "nonce": "5a3f3701-e295-4635-bef5-559f199abd03",
  "claims": {
    "vc": {
      "essential": true,
      "value": [
        "VerifiableCredential",
        "VerifiableIdCredential"
      ]
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
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp2aWQ6MHg5NDkzN2ZBM2Y2NWQ1RTkwNzkxM2EzQWRBZmFhZDFlQmY5RERhQzFiI2tleS0xIn0.eyJpYXQiOjE2MDQ1NTY3MDEsImV4cCI6MTYwNDU1NzAwMSwiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZSIsInN1YiI6Ikt1RGp5VXJobUFJa051T2VkQ0VKbzNZVHlsQUxCWUtmc1lVS1FOd1YzdEUiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvZGVtby9zcGFuaXNoLXVuaXZlcnNpdHkiLCJub25jZSI6IjVhM2YzNzAxLWUyOTUtNDYzNS1iZWY1LTU1OWYxOTlhYmQwMyIsInN1Yl9qd2siOnsia2lkIjoiZGlkOnZpZDoweDk0OTM3ZkEzZjY1ZDVFOTA3OTEzYTNBZEFmYWFkMWVCZjlERGFDMWIja2V5LTEiLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJjYTM3NTU4YWY5YmRmYTIxNTVlYTA4ODcwZGRiOWY2NDUyMzBmNjg0ODAzZmY2MDQyYzZmMzM1YzNiN2I4YzAiLCJ5IjoiNzg3MDBmYjc0NWExNWU0NjU4ZDJjYTIwNTJlYjQ3ZmRkNDgyMTZmYTFjY2ZlYjZjNzM4NzRjMTViNmZkYmRkMyJ9LCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vYXBpLnZpZGNoYWluLm5ldC9jcmVkZW50aWFscy92ZXJpZmlhYmxlSWQvdjEiXSwiaWQiOiJodHRwczovL2FwaS52aWRjaGFpbi5uZXQvYXBpL3YxL3NjaGVtYXMvMjM5MSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlSWRDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDp2aWQ6MHg1MjA4NDMxQzZFQzJlYzQwOTdhZUE3MTgyYkI5MmQwMTg3NjY0OThjIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6dmlkOjB4ODcwN0NDYTgzNUM5NjEzMzREM0Y2NDUwQzZhNjFhMEFENjU5MjQ2MCIsImZpcnN0TmFtZSI6IkV2YSIsImxhc3ROYW1lIjoiTW9ucm9lIiwiZ2VuZGVyIjoiRmVtYWxlIiwiZGF0ZU9mQmlydGgiOiIxMi8xMS8xOTcwIiwicGxhY2VPZkJpcnRoIjoiTWFkcmlkIiwiY3VycmVudEFkZHJlc3MiOiJBcmFnbyAxNzkgNGEiLCJjaXR5IjoiQmFyY2Vsb25hIiwic3RhdGUiOiJDYXRhbHXDsWEiLCJ6aXAiOiIwODAxMSJ9LCJpc3N1YW5jZURhdGUiOiIyMDE5LTExLTE3VDE0OjAwOjAwWiIsInByb29mIjp7InR5cGUiOiJFY2RzYVNlY3AyNTZrMVNpZ25hdHVyZTIwMTkiLCJjcmVhdGVkIjoiMjAxOS0xMS0xN1QxNDowMDowMFoiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6dmlkOjB4NTIwODQzMUM2RUMyZWM0MDk3YWVBNzE4MmJCOTJkMDE4NzY2NDk4YyNrZXktMSIsImp3cyI6ImV5SmhiR2NpT2lKRlV6STFOa3N0VWlJc0luUjVjQ0k2SWtwWFZDSXNJbXRwWkNJNkltUnBaRHAyYVdRNk1IZ3pZV1F6WmtZNFJUVmhRamhFTmprelF6STRRbVJFT1VJME4yVmtSREZtTnpRME5VWTRZek5HSTJ0bGVTMHhJbjAuZXlKcFlYUWlPakUxT1RFM09UazFNRFFzSW5aaklqcDdJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDNZeElpd2lhSFIwY0hNNkx5OWhjR2t1ZG1sa1kyaGhhVzR1Ym1WMEwyTnlaV1JsYm5ScFlXeHpMM1psY21sbWFXRmliR1V0YVdRdmRqRWlYU3dpYVdRaU9pSm9kSFJ3Y3pvdkwyRndhUzUyYVdSamFHRnBiaTV1WlhRdllYQnBMM1l4TDNOamFHVnRZWE12TWpNNU1TSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKV1pYSnBabWxoWW14bFNXUkRjbVZrWlc1MGFXRnNJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltbGtJam9pWkdsa09uWnBaRG93ZURReVlqZzVPRVV5TjBNMU5tVTNaRFZCTW1RMFJUWTBObVJDTW1RME1UaENSRFZETVRjd1l6UWlMQ0ptYVhKemRFNWhiV1VpT2lKRmRtRWlMQ0pzWVhOMFRtRnRaU0k2SWsxdmJuSnZaU0lzSW1kbGJtUmxjaUk2SWtabGJXRnNaU0lzSW1SaGRHVlBaa0pwY25Sb0lqb2lNVEl2TVRFdk1UazNNQ0lzSW5Cc1lXTmxUMlpDYVhKMGFDSTZJazFoWkhKcFpDSXNJbU4xY25KbGJuUkJaR1J5WlhOeklqb2lRWEpoWjI4Z01UYzVJRFJoSWl3aVkybDBlU0k2SWtKaGNtTmxiRzl1WVNJc0luTjBZWFJsSWpvaVEyRjBZV3h2Ym1saElpd2llbWx3SWpvaU1EZ3dNVEVpZlN3aWFYTnpkV1Z5SWpvaVpHbGtPblpwWkRvd2VETmhaRE5tUmpoRk5XRkNPRVEyT1RORE1qaENaRVE1UWpRM1pXUkVNV1kzTkRRMVJqaGpNMFlpZlN3aWFYTnpJam9pWkdsa09uWnBaRG93ZUROaFpETm1SamhGTldGQ09FUTJPVE5ETWpoQ1pFUTVRalEzWldSRU1XWTNORFExUmpoak0wWWlmUS5CN2U0WnA5akdMRFhUUkc4SUQxajBfRVZ3b1FsSV9YRHpTYWdLV21EUi1JTmpNVlNGRzExNDJhc0MxcjVSZWROdXUzU1I4VkljRTl5cmJEdzljUnVFUUEifX1dLCJwcm9vZiI6eyJ0eXBlIjoiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5IiwiY3JlYXRlZCI6IjIwMTktMDYtMjJUMTQ6MTE6NDRaIiwicHJvb2ZQdXJwb3NlIjoiYXNzZXJ0aW9uTWV0aG9kIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOnZpZDoweDE2MDQ4QjgzRkFkYUNkQ0IyMDE5OEFCYzQ1NTYyRGYxQTNlMjg5YUYja2V5LTEiLCJqd3MiOiJleUpoYkdjaU9pSkZVekkxTmtzaWZRLmV5SnpkV0lpT2lKRlFsTkpJREl3TVRraWZRLm9nZ0UzZnQza0pZUEdHYTllQmlicGJqZ2VKWHc0ZkxiVk1vdVZvTTJOZmNEeHNsX1VVVUlhcnNTMVZwQm9ZRXM3czljQmxjNHVDMEVibkpDSGZWSkl3In19fQ.SAymOc-Ke7UcTC_FnGxl43LAP37d0cQUFwIna6nec_uUD8hewQX6P-7fLsAaxQt1ZQkZrQgyfUaZmTpE3bnvsAA

// Header
{
  "alg": "ES256K-R",
  "typ": "JWT",
  "kid": "did:vid:0x94937fA3f65d5E907913a3AdAfaad1eBf9DDaC1b#key-1"
}
// Payload
{
  "iat": 1604556701,
  "exp": 1604557001,
  "iss": "https://self-issued.me",
  "sub": "KuDjyUrhmAIkNuOedCEJo3YTylALBYKfsYUKQNwV3tE",
  "aud": "http://localhost:8080/demo/spanish-university",
  "nonce": "5a3f3701-e295-4635-bef5-559f199abd03",
  "sub_jwk": {
    "kid": "did:vid:0x94937fA3f65d5E907913a3AdAfaad1eBf9DDaC1b#key-1",
    "kty": "EC",
    "crv": "secp256k1",
    "x": "ca37558af9bdfa2155ea08870ddb9f645230f684803ff6042c6f335c3b7b8c0",
    "y": "78700fb745a15e4658d2ca2052eb47fdd48216fa1ccfeb6c73874c15b6fdbdd3"
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
