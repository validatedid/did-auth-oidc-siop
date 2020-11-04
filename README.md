# Validated ID DID SIOP Auth Library

> This is a ValidatedID version of did-auth protocol to authenticate a user and a Relaying Party using vid DIDs.

The current DID Auth implementation follows [DID SIOP Auth](https://identity.foundation/did-siop/), which uses two JSON Web Tokens (JWT) signed by both two parties DID keys in a double challenge-response authentication.

Current version supports only `ES256k-R` algorithm (the EC secp256k1).

> Note: This version implemented does NOT have support for custom claims. (i.e. using VerifiableID)

## Table of Contents

1. [Installation](#Installation)
2. [Authentication Flow](#Authentication-Flow)
3. [Usage](#Usage)
4. [Library Test](#Library-Test)

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

- An entity with a valid did:vid already generated wants to authenticate to a Relying Party (RP). For instance, by clicking on a `Login` button in RP's webpage.
- RP will use this library to create a DidAuthRequestCall URI Request calling `VidDidAuth.createUriRequest` with this payload:

```javascript
const didAuthRequestCall: DidAuthRequestCall = {
  requestUri: "https://app.example.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV", // Endpoint where the RP will store the token so the entity can access to it later on
  redirectUri: "https://app.example.net/demo/spanish-university", // Redirect URI after successful authentication
  signatureUri: "https://api.vidchain.net/wallet/v1/signatures", // VID wallet endpoint to create a signature
  authZToken: RPAuthZToken, // RP Access token received after calling VID wallet sessions endpoint
};

const { uri, nonce } = await VidDidAuth.createUriRequest(didAuthRequestCall);
```

- RP receives an Open ID URI and nonce as a result:

<!-- prettier-ignore-start -->
```html
openid://?scope=openid%20did_authn&response_type=id_token&client_id=<redirectUri>&requestUri=<requestUri>
```
<!-- prettier-ignore-end -->

> _Note 1_: RP needs to store embbeded jwt in requestUri endpoint so the entity can retrieve it. For example, when a user scans this information from QR code using a wallet.
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

- User needs to do a GET REST API call to `redirectUri` to receive the Jwt. This is out of scope of this library. Once the user has the Jwt, then the library is again used on this side to verify the token and create the Response token:

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
const userDid = "did:vid:0x96A28e3Ce8Ef23F0e0aeFE82AA4015E1edABaaA0";
// Relying Party DID
const enterpriseDid = "did:vid:0xc04F03A93446BE9Cf57aFEc5de1f3FBeb624a21B";
```

### Creating VID DID-Auth Request URI

Creates a DidAuth Request URI with a JWT signed with the RP DID key, using wallet backend endpoint URI given as a parameter `signatureUri` with an authorization token `authZToken`.

```js
import { DidAuthRequestCall, vidDidAuth } from "@validatedid/did-auth";

const didAuthRequestCall: DidAuthRequestCall = {
  redirectUri: "https://localhost:8080/demo/spanish-university",
  signatureUri: "http://localhost:9000/wallet/v1/signatures",
  authZToken: enterpriseAuthZToken,
};

const { uri, nonce } = await vidDidAuth.createUriRequest(didAuthRequestCall);
```

### Verifying VID DID-Auth Request

Pass in a DID Auth Request JWT to verify the token:

```js
import { DidAuthRequestPayload, vidDidAuth } from "@validatedid/did-auth";

const payload: DidAuthRequestPayload = await vidDidAuth.verifyDidAuthRequest(
  didAuthJwt
);
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
```

### Verifying VID DID-Auth Response

Pass in a DID Auth Response JWT to verify the token:

> Note: Response code is 204. So, no response data is returned.

```js
import { DidAuthResponsePayload, vidDidAuth } from "@validatedid/did-auth";

const response = await vidDidAuth.verifyDidAuthResponse(didAuthJwt);
```

## Library Test

To run `e2e` you need to set these two environment variables either in a `.env` or passing as a parameter to `npm run test:e2e`:

- `DID_REGISTRY_SC_ADDRESS` as the current Smart Contract Address
- `WALLET_API_URL` as the base url for wallet-api. i.e.: `http://localhost:9000`

You can use the `.env.example` from the repo and renamed it to `.env`.

```bash
# run tests
$ npm run test

# unit tests
$ npm run test:unit

# e2e tests
$ npm run test:e2e
```
