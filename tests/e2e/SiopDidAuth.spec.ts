import { parse } from "querystring";
import * as didJwt from "@validatedid/did-jwt";
import * as dotenv from "dotenv";
import * as siopDidAuth from "../../src";
import {
  DidAuthTypes,
  DidAuthJwk,
  DidAuthUtil,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
} from "../../src";
import {
  getLegalEntityTestAuthZToken,
  getPublicJWKFromDid,
  getUserEntityTestAuthZToken,
  mockedKeyAndDid,
} from "../AuxTest";
import * as mockedData from "../data/mockedData";
import {
  DidAuthResponseMode,
  DidAuthVerifyOpts,
} from "../../src/interfaces/DIDAuth.types";
import { getPublicJWKFromPublicHex } from "../../src/util/JWK";

dotenv.config();

describe("VidDidAuth tests should", () => {
  describe("create Uri Requests tests with", () => {
    it("a JWT request by value", async () => {
      expect.assertions(10);
      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          hexPrivateKey:
            "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
          did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
          kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1",
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const uriRequest = await siopDidAuth.createUriRequest(opts);
      expect(uriRequest).toBeDefined();
      expect(uriRequest).toHaveProperty("urlEncoded");
      expect(uriRequest).toHaveProperty("encoding");
      expect(uriRequest).toHaveProperty("urlEncoded");
      const uriDecoded = decodeURIComponent(uriRequest.urlEncoded);
      expect(uriDecoded).toContain(`openid://`);
      expect(uriDecoded).toContain(
        `?response_type=${DidAuthTypes.DidAuthResponseType.ID_TOKEN}`
      );
      expect(uriDecoded).toContain(`&client_id=${opts.redirectUri}`);
      expect(uriDecoded).toContain(
        `&scope=${DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN}`
      );
      expect(uriDecoded).toContain(`&request=`);
      const data = parse(uriDecoded);
      expect(data.request).toBeDefined();
    });

    it("a JWT request by reference", async () => {
      expect.assertions(12);
      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          hexPrivateKey:
            "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
          did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
          kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1",
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const uriRequest = await siopDidAuth.createUriRequest(opts);
      expect(uriRequest).toBeDefined();
      expect(uriRequest).toHaveProperty("urlEncoded");
      expect(uriRequest).toHaveProperty("encoding");
      expect(uriRequest).toHaveProperty("urlEncoded");
      const uriDecoded = decodeURIComponent(uriRequest.urlEncoded);
      expect(uriDecoded).toContain(`openid://`);
      expect(uriDecoded).toContain(
        `?response_type=${DidAuthTypes.DidAuthResponseType.ID_TOKEN}`
      );
      expect(uriDecoded).toContain(`&client_id=${opts.redirectUri}`);
      expect(uriDecoded).toContain(
        `&scope=${DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN}`
      );
      expect(uriDecoded).toContain(`&requestUri=`);
      const data = parse(uriDecoded);
      expect(data.requestUri).toStrictEqual(opts.requestObjectBy.referenceUri);
      expect(uriRequest).toHaveProperty("jwt");
      expect(uriRequest.jwt).toBeDefined();
    });
  });

  describe("create a Did Auth Request JWT with", () => {
    it("a JWT request by reference that contains the required parameters", async () => {
      expect.assertions(7);
      const { hexPrivateKey, did } = mockedKeyAndDid();

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          hexPrivateKey,
          did,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const { jwt, nonce, state } = await siopDidAuth.createDidAuthRequest(
        opts
      );

      expect(jwt).toBeDefined();
      expect(nonce).toBeDefined();
      expect(state).toBeDefined();
      const { header, payload } = didJwt.decodeJwt(jwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${did}#keys-1`;
      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.state = expect.any(String) as string;
      expectedPayload.client_id = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.registration = {
        jwks: DidAuthJwk.getPublicJWKFromPrivateHex(
          hexPrivateKey,
          expectedHeader.kid
        ),
      };
      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60);
    });

    it("a JWT request by reference that contains all possible parameters signing internally", async () => {
      expect.assertions(5);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-2`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        responseMode: DidAuthTypes.DidAuthResponseMode.FORM_POST,
        responseContext: DidAuthTypes.DidAuthResponseContext.WALLET,
        state,
        nonce,
        claims: mockedData.verifiableIdOidcClaim,
        keySigningAlgorithm: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
      };

      const { jwt } = await siopDidAuth.createDidAuthRequest(opts);

      expect(jwt).toBeDefined();
      const { header, payload } = didJwt.decodeJwt(jwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${did}#key-2`;
      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD_CLAIMS;
      expectedPayload.iss = did;
      expectedPayload.nonce = nonce;
      expectedPayload.state = state;
      expectedPayload.client_id = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.registration = {
        jwks: DidAuthJwk.getPublicJWKFromPrivateHex(
          hexPrivateKey,
          expectedHeader.kid
        ),
      };
      expectedPayload.response_mode =
        DidAuthTypes.DidAuthResponseMode.FORM_POST;
      expectedPayload.response_context =
        DidAuthTypes.DidAuthResponseContext.WALLET;
      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60);
    });
  });
  describe("create Uri Response tests with", () => {
    it("an id_token and state using the default response_mode=fragment with only required params", async () => {
      expect.assertions(10);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const uriResponse = await siopDidAuth.createUriResponse(opts);
      expect(uriResponse).toBeDefined();
      expect(uriResponse).toHaveProperty("urlEncoded");
      expect(uriResponse).toHaveProperty("encoding");
      expect(uriResponse).toHaveProperty("response_mode");
      expect(uriResponse.encoding).toStrictEqual(
        DidAuthTypes.UrlEncodingFormat.FORM_URL_ENCODED
      );
      expect(uriResponse.response_mode).toStrictEqual(
        DidAuthTypes.DidAuthResponseMode.FRAGMENT
      );
      const urlDecoded = decodeURIComponent(uriResponse.urlEncoded);
      expect(urlDecoded).toContain(`https://app.example/demo`);
      const splitUrl = urlDecoded.split("#");
      const data = parse(splitUrl[1]);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
    it("an id_token and state using response_mode=query with only required params", async () => {
      expect.assertions(10);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.QUERY,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const uriResponse = await siopDidAuth.createUriResponse(opts);
      expect(uriResponse).toBeDefined();
      expect(uriResponse).toHaveProperty("urlEncoded");
      expect(uriResponse).toHaveProperty("encoding");
      expect(uriResponse).toHaveProperty("response_mode");
      expect(uriResponse.encoding).toStrictEqual(
        DidAuthTypes.UrlEncodingFormat.FORM_URL_ENCODED
      );
      expect(uriResponse.response_mode).toStrictEqual(
        DidAuthTypes.DidAuthResponseMode.QUERY
      );
      const urlDecoded = decodeURIComponent(uriResponse.urlEncoded);
      expect(urlDecoded).toContain(`https://app.example/demo`);
      const splitUrl = urlDecoded.split("?");
      const data = parse(splitUrl[1]);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
    it("an id_token and state using response_mode=form_post with only required params", async () => {
      expect.assertions(11);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const uriResponse = await siopDidAuth.createUriResponse(opts);
      expect(uriResponse).toBeDefined();
      expect(uriResponse).toHaveProperty("urlEncoded");
      expect(uriResponse).toHaveProperty("encoding");
      expect(uriResponse).toHaveProperty("response_mode");
      expect(uriResponse).toHaveProperty("bodyEncoded");
      expect(uriResponse.encoding).toStrictEqual(
        DidAuthTypes.UrlEncodingFormat.FORM_URL_ENCODED
      );
      expect(uriResponse.response_mode).toStrictEqual(
        DidAuthTypes.DidAuthResponseMode.FORM_POST
      );
      expect(decodeURIComponent(uriResponse.urlEncoded)).toContain(
        `https://app.example/demo`
      );
      const urlDecoded = decodeURIComponent(uriResponse.bodyEncoded);
      const data = parse(urlDecoded);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
  });
  describe("verifyDidAuthRequest tests should", () => {
    it("verify internally a DidAuth Request JWT", async () => {
      expect.assertions(7);
      const { hexPrivateKey, did } = mockedKeyAndDid();

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          hexPrivateKey,
          did,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const { jwt } = await siopDidAuth.createDidAuthRequest(opts);
      expect(jwt).toBeDefined();

      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          registry: process.env.DID_REGISTRY_SC_ADDRESS,
          rpcUrl: process.env.DID_PROVIDER_RPC_URL,
        },
      };
      const validationResponse = await verifyDidAuthRequest(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
      expect(validationResponse.signatureValidation).toBe(true);
      expect(validationResponse.payload).toBeDefined();

      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.state = expect.any(String) as string;
      expectedPayload.client_id = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.registration = {
        jwks: DidAuthJwk.getPublicJWKFromPrivateHex(
          hexPrivateKey,
          `${did}#keys-1`
        ),
      };

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });

    it("verify internally a DidAuth Response JWT", async () => {
      expect.assertions(7);

      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const jwt = await siopDidAuth.createDidAuthResponse(opts);
      expect(jwt).toBeDefined();

      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          registry: process.env.DID_REGISTRY_SC_ADDRESS,
          rpcUrl: process.env.DID_PROVIDER_RPC_URL,
        },
        nonce,
      };
      const validationResponse = await verifyDidAuthResponse(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
      expect(validationResponse.signatureValidation).toBe(true);
      expect(validationResponse.payload).toBeDefined();

      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD;
      expectedPayload.did = did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.aud = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.sub = expect.any(String) as string;
      expectedPayload.sub_jwk = DidAuthJwk.getPublicJWKFromPrivateHex(
        hexPrivateKey,
        `${did}#keys-1`
      );

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });

    it("verify externally a DidAuth Response JWT generated internally", async () => {
      expect.assertions(7);
      const WALLET_API_BASE_URL = process.env.WALLET_API_URL;
      const entityAA = await getLegalEntityTestAuthZToken("COMPANY E2E INC");
      const authZToken = entityAA.jwt;
      const {
        hexPrivateKey,
        did,
        hexPublicKey,
      } = await getUserEntityTestAuthZToken();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const jwt = await siopDidAuth.createDidAuthResponse(opts);
      expect(jwt).toBeDefined();
      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
        },
        nonce,
        redirectUri: opts.redirectUri,
      };
      const validationResponse = await verifyDidAuthResponse(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
      expect(validationResponse.signatureValidation).toBe(true);
      expect(validationResponse.payload).toBeDefined();

      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD;
      expectedPayload.did = did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.aud = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.sub = expect.any(String) as string;
      expectedPayload.sub_jwk = getPublicJWKFromPublicHex(
        hexPublicKey,
        opts.signatureType.kid
      );

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });

    it("verify externally a DidAuth Response JWT generated externally with a test entity", async () => {
      expect.assertions(7);
      const WALLET_API_BASE_URL = process.env.WALLET_API_URL;
      const entityAA = await getLegalEntityTestAuthZToken("COMPANY E2E INC");
      const authZToken = entityAA.jwt;
      const { did } = entityAA;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
          did,
          authZToken,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
          referenceUri: `${WALLET_API_BASE_URL}/api/v1/identifiers/${did};transform-keys=jwks`,
        },
        did,
      };

      const jwt = await siopDidAuth.createDidAuthResponse(opts);
      expect(jwt).toBeDefined();

      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
        },
        nonce,
        redirectUri: opts.redirectUri,
      };
      const validationResponse = await verifyDidAuthResponse(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
      expect(validationResponse.signatureValidation).toBe(true);
      expect(validationResponse.payload).toBeDefined();

      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD;
      expectedPayload.did = did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.aud = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.sub = expect.any(String) as string;
      expectedPayload.sub_jwk = await getPublicJWKFromDid(did);

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });
  });
});
