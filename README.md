![EBSI Logo](https://ec.europa.eu/cefdigital/wiki/images/logo/default-space-logo.svg)

# EBSI DID Auth Library

> Warning: Experimental version of validatedID did-auth protocol to authenticate a user and a Relaying Party using vid DIDs.

## Table of Contents

1. [Installation](#Installation)
2. [Authentication Flow](#Authentication-Flow)
3. [Usage](#Usage)
4. [Library Test](#Library-Test)
5. [Licensing](#Licensing)

## Installation

```bash
npm install @cef-ebsi/did-auth
```

or if you use `yarn`

```bash
yarn add @cef-ebsi/did-auth
```

## Authentication Flow

The current EBSI DID Auth implementation follows [DID Auth RFC Section 4](https://ec.europa.eu/cefdigital/wiki/pages/viewpage.action?spaceKey=BLOCKCHAININT&title=RFC+DID+Auth+in+EBSI+V1#RFCDIDAuthinEBSIV1-UserAuthenticationusingVerifiableID), which uses two JSON Web Tokens (JWT) signed by both two parties DID keys in a double challenge-response authentication.
Current version supports only `ES256k-R` algorithm (the EC secp256k1) and `did:ebsi` DID method.

> Note: This version implemented does NOT have support for custom claims. (i.e. using VerifiableID)

The DID Auth flow has the following steps:

- A user, with a valid ebsi:did already generated, accesses on an Institution web site, Relying Party (RP) from now on, and clicks to a `Login` button
- RP creates an EbsiDidAuth URI Request calling `EbsiDidAuth.createUriRequest` with this payload:

```javascript
const didAuthRequestCall: DidAuthRequestCall = {
  redirectUri: "https://app.ebsi.xyz/demo/spanish-university", // Redirect URI after successful authentication
  signatureUri: "https://app.ebsi.xyz/wallet/v1/signatures", // EBSI wallet endpoint to create a signature
  authZToken: RPAuthZToken, // RP Access token received after calling EBSI wallet sessions endpoint
};

// Creates a URI using the wallet backend that manages entity DID keys
const { uri, nonce } = await EbsiDidAuth.createUriRequest(didAuthRequestCall);
```

- RP receives an Open ID URI and nonce as a result:

<!-- prettier-ignore-start -->
```html
openid://?scope=openid%20did_authn&response_type=id_token&client_id=<redirectUri>&request=<Signed JWT Request Object>
```
<!-- prettier-ignore-end -->

> _Note_: RP needs to store `nonce`, found inside the Request token to be used on the response validation process.

- RP redirects to the wallet front-end passing the DID-Auth URI as a parameter:
<!-- prettier-ignore -->

<!-- prettier-ignore-start -->
```html
https://app.ebsi.xyz/demo/wallet?did-auth=openid://?scope=openid%20did_authn&response_type=id_token&client_id=<redirectUri>&request=<Signed JWT Request Object>
```
<!-- prettier-ignore-end -->

- User wallet frontend parses the received EBSI DID Auth Request URI to obtain `client_id` and `request` URL parameters to be used to verify the token and create the Response token:

```javascript
const params = new URLSearchParams(didAuthUri);
const redirectUri = params.get("client_id");
const didAuthRequestJwt = params.get("request");
const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS;
const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";

// VERIFY DID-AUTH REQUEST
const requestPayload: DidAuthRequestPayload = await EbsiDidAuth.verifyDidAuthRequest(
  didAuthRequestJwt,
  RPC_ADDRESS,
  RPC_PROVIDER
);
```

- After a successful validation, user creates an EBSI DID Auth Response JWT token calling `EbsiDidAuth.createDidAuthResponse`, reusing the Request `nonce`.

```javascript
// CREATE A DID-AUTH RESPONSE
const didAuthResponseCall: DidAuthResponseCall = {
  hexPrivatekey: userPrivateKey, // private key managed by the user. Should be passed in hexadecimal format
  did: "did:ebsi:0x226e2e2223333c2e4c65652e452d412d50611111", // User DID
  nonce: requestPayload.nonce, // same nonce received as a Request Payload after verifying it
  redirectUri, // parsed URI from the DID Auth Request payload
};
const didAuthResponseJwt = await EbsiDidAuth.createDidAuthResponse(
  didAuthResponseCall
);
```

- User redirects to the RP `redirectUri` URI passing the Response token as a parameter:

<!-- prettier-ignore-start -->
```html
https://app.ebsi.xyz/demo/spanish-university?response=<Signed JWT Response Object>
```
<!-- prettier-ignore-end -->

- RP verifies the DID Auth Response token calling `EbsiDidAuth.verifyDidAuthResponse` passing the stored nonce:

```javascript
const response = await EbsiDidAuth.verifyDidAuthResponse(
  didAuthResponseJwt, // DID Auth Response token to be validate
  "https://app.ebsi.xyz/wallet/signature-validations", // EBSI wallet endpoint to validate a signature
  RPAuthZToken, // RP Access token received after calling EBSI wallet sessions endpoint,
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

It is assumed that either the user and the Relying Party (RP) have an EBSI-DID and can use their private keys to sign a given payload.

For instance:

```js
// User DID
const userDid = "did:ebsi:0xcAe6EFa4461262842BB58188579Ef2602c7A44fC";
// Relying Party DID
const enterpriseDid = "did:ebsi:0xDe07DBEe84cCB1F75A09e96b1f995560b7Cdf5aa";
```

### Creating an EBSI DID-Auth Request URI

Creates a DidAuth Request URI with a JWT signed with the RP DID key, using wallet backend endpoint URI given as a parameter `signatureUri` with an authorization token `authZToken`.

```js
import { DidAuthRequestCall, EbsiDidAuth } from "@cef-ebsi/did-auth";

const didAuthRequestCall: DidAuthRequestCall = {
  redirectUri: "https://localhost:8080/demo/spanish-university",
  signatureUri: "http://localhost:9000/wallet/v1/signatures",
  authZToken: enterpriseAuthZToken,
};

const { uri, nonce } = await EbsiDidAuth.createUriRequest(didAuthRequestCall);
console.log(uri);
// openid://&scope=openid did_authn?response_type=id_token&client_id=https://localhost:8080/demo/spanish-university&request=eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDplYnNpOjB4MDNBN2UzMjhBZGM5NjZiNUI1ODRiOUFjREI2ZmVBNWY0NEFkNUMwYiNrZXktMSJ9.eyJpYXQiOjE1ODg2MDI2NjksImV4cCI6MTU4ODYwMjk2OSwiaXNzIjoiZGlkOmVic2k6MHgwM0E3ZTMyOEFkYzk2NmI1QjU4NGI5QWNEQjZmZUE1ZjQ0QWQ1QzBiIiwic2NvcGUiOiJvcGVuaWQgZGlkX2F1dGhuIiwicmVzcG9uc2VfdHlwZSI6ImlkX3Rva2VuIiwiY2xpZW50X2lkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODA4MC9kZW1vL3NwYW5pc2gtdW5pdmVyc2l0eSIsIm5vbmNlIjoiNWRjNjNjZmYtYTYzNy00ZDEyLWE1OWYtOTkxZjAwNGJkMmVhIn0.z9_I0gtKs8Q9LwnxQyAgtN3DY65nwYIzEAs3viRIM7ItHZcng5LjI-BoFrhcLyRk7vgCGEp1F3ASO9qp0jIhPgA
```

### Verifying an EBSI DID-Auth Request

Pass in an EBSI DID Auth Request JWT to verify the token:

```js
import { DidAuthRequestPayload, EbsiDidAuth } from "@cef-ebsi/did-auth";

const payload: DidAuthRequestPayload = await EbsiDidAuth.verifyDidAuthRequest(
  didAuthJwt
);
console.log(payload);
/*
{
  "iat": 1587388006,
  "exp": 1587388306,
  "iss": "did:ebsi:0xc7281C0412DbaA8e6073332FF2F4B6c1FFF9d74f",
  "scope": "openid did_authn",
  "response_type": "id_token",
  "client_id": "https://localhost:8080/demo/spanish-university",
  "nonce": "fa2ce561-9abd-4cbb-87b5-60d24fbabc61"
}
*/
```

### Creating an EBSI DID-Auth Response

Creates a DID Auth Response JWT signed with the user DID key, passed directly as a hexadecimal format.

```js
import { DidAuthResponseCall, EbsiDidAuth } from "@cef-ebsi/did-auth";

const didAuthResponseCall: DidAuthResponseCall = {
  hexPrivatekey: getHexPrivateKey(testKeyUser.key),
  did: testKeyUser.did,
  nonce: requestPayload.nonce,
  redirectUri,
};
const didAuthResponseJwt = await EbsiDidAuth.createDidAuthResponse(
  didAuthResponseCall
);
console.log(didAuthJwt);
// eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDplYnNpOjB4M0FBZjYzODk0ZkY0NkU0OUQ4NDEwMWI4OTVlQjE5RjA2QTlhN0MyMiNrZXktMSJ9.eyJpYXQiOjE1ODcyNzE2NjIsImV4cCI6MTU4NzI3MTk2MiwiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZSIsInN1YiI6Ik01cGlYOFFWRDd4cnJ0MVJVT19OS2pQUGR2VFNwdzhVX0tPZUE2RlR3TkkiLCJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo4MDgwL2RlbW8vc3BhbmlzaC11bml2ZXJzaXR5Iiwibm9uY2UiOiI2ODI2YjdmMi1jNGQzLTQ3OWItYTU2NC04ZWRkYzQwNmYzYWMiLCJzdWJfandrIjp7ImtpZCI6ImRpZDplYnNpOjB4M0FBZjYzODk0ZkY0NkU0OUQ4NDEwMWI4OTVlQjE5RjA2QTlhN0MyMiNrZXktMSIsImt0eSI6IkVDIiwiY3J2Ijoic2VjcDI1NmsxIiwieCI6IjM0NjgwMGVhOWExMzgyOWU5M2JjZjllZWM2NmU2ZjIzMDM2MGU0YTI5ZjRiMzI0Yzc5YmQ3MGQxOTkyZjc4MWQiLCJ5IjoiMjNhYTg1ZjZjNDI4MDk0ZTc0OTAxNGFjNDU4OWQyNDNjZWViMjczMmJmYTcyMDcwOTkwMDljODFkYjc1NmEwOCJ9fQ.NEmyZ28qkOdSxIb1sDm5KLSuVvDtRjZm4aoYl17ASDWjcUHus-4ANJB2-Of9q2PROcAWpNoPnkdXX5pVtlZ48AA
```

### Verifying an EBSI DID-Auth Response

Pass in an EBSI DID Auth Response JWT to verify the token:

> Note: Response code is 204. So, no response data is returned.

```js
import { DidAuthResponsePayload, EbsiDidAuth } from "@cef-ebsi/did-auth";

const response = await EbsiDidAuth.verifyDidAuthResponse(didAuthJwt);
console.log(response);

/*
{
  signatureValidation: true,
}
*/
```

## Library Test

To run `e2e` you need to set these two environment variables either in a `.env` or passing as a parameter to `npm run test:e2e`:

- `DID_REGISTRY_SC_ADDRESS` as the current Smart Contract Address
- `WALLET_API_URL` as the base url for wallet-api. i.e.: `http://localhost:9000`

You can use the `.env.example` from the repo and renamed it to `.env`.

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# all tests
$ npm run test:all
```

## Licensing

Copyright (c) 2019 European Commission  
Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence");
You may not use this work except in compliance with the Licence.
You may obtain a copy of the Licence at:

- <https://joinup.ec.europa.eu/page/eupl-text-11-12>

Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the Licence for the specific language governing permissions and limitations under the Licence.
