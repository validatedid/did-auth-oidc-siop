import { parse } from "querystring";
import * as didJwt from "did-jwt";
import * as dotenv from "dotenv";
import { decodeJWT } from "did-jwt";
import * as siopDidAuth from "../../src";
import {
  DidAuthTypes,
  DidAuthJwk,
  DidAuthUtil,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
} from "../../src";
import { signDidAuthInternal } from "../../src/AuxDidAuth";
import {
  getLegalEntityTestAuthZToken,
  getPublicJWKFromDid,
  getUserEntityTestAuthZToken,
  getUserEntityTestAuthZTokenDidKey,
  getKidFromDID,
} from "../AuxTest";
import * as mockedData from "../data/mockedData";
import {
  DidAuthResponseMode,
  DidAuthVerifyOpts,
  DidAuthResponseIss,
} from "../../src/interfaces/DIDAuth.types";
import { getPublicJWKFromPublicHex } from "../../src/util/JWK";

dotenv.config();
jest.setTimeout(30000);

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
          did: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
          kid: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1",
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
      const uriDecoded = decodeURI(uriRequest.urlEncoded);
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
          did: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
          kid: "did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1",
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
      const uriDecoded = decodeURI(uriRequest.urlEncoded);
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
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();

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
      const { header, payload } = didJwt.decodeJWT(jwt);

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
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
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
      const { header, payload } = didJwt.decodeJWT(jwt);

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
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
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
      const urlDecoded = decodeURI(uriResponse.urlEncoded);
      expect(urlDecoded).toContain(`https://app.example/demo`);
      const splitUrl = urlDecoded.split("#");
      const data = parse(splitUrl[1]);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
    it("an id_token and state using response_mode=query with only required params", async () => {
      expect.assertions(10);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
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
      const urlDecoded = decodeURI(uriResponse.urlEncoded);
      expect(urlDecoded).toContain(`https://app.example/demo`);
      const splitUrl = urlDecoded.split("?");
      const data = parse(splitUrl[1]);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
    it("an id_token and state using response_mode=form_post with only required params", async () => {
      expect.assertions(11);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
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
      expect(decodeURI(uriResponse.urlEncoded)).toContain(
        `https://app.example/demo`
      );
      const urlDecoded = decodeURI(uriResponse.bodyEncoded);
      const data = parse(urlDecoded);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
  });
  describe("verifyDidAuthRequest tests should", () => {
    it("verify internally a DidAuth Request JWT", async () => {
      expect.assertions(7);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();

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
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
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
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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
      const entityAA = await getLegalEntityTestAuthZToken(
        "LEGAL ENTITY TEST 007"
      );
      const authZToken = entityAA.jwt;
      const { hexPrivateKey, did, hexPublicKey } =
        await getUserEntityTestAuthZToken();
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
          verifyUri: `https://dev.vidchain.net/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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
      const entityAA = await getLegalEntityTestAuthZToken(
        "LEGAL ENTITY TEST 007"
      );
      const authZToken = entityAA.jwt;
      const { did } = entityAA;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);

      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          signatureUri: `https://dev.vidchain.net/api/v1/signatures`,
          did,
          authZToken,
          kid: `${did}#keys-1`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${did};transform-keys=jwks`,
        },
        did,
      };

      const jwt = await siopDidAuth.createDidAuthResponse(opts);
      expect(jwt).toBeDefined();

      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `https://dev.vidchain.net/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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

describe("VidDidAuth using did:key tests should", () => {
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
            "d474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3",
          did: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc",
          kid: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#keys-1",
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
      const uriDecoded = decodeURI(uriRequest.urlEncoded);
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
            "d474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3",
          did: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc",
          kid: "did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#keys-1",
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
      const uriDecoded = decodeURI(uriRequest.urlEncoded);
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
  describe("verifyDidAuthRequest tests should", () => {
    it("verify externally DidAuth Request JWT", async () => {
      expect.assertions(3);
      const entityAA = await getLegalEntityTestAuthZToken(
        "LEGAL ENTITY TEST 007"
      );
      const authZToken = entityAA.jwt;
      const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const { jwt } = await siopDidAuth.createDidAuthRequest(opts);
      expect(jwt).toBeDefined();
      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `https://dev.vidchain.net/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
        },
        nonce,
        redirectUri: opts.redirectUri,
      };
      const validationResponse = await verifyDidAuthRequest(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
      expect(validationResponse.signatureValidation).toBe(true);
    });

    it("verify internally DidAuth Request JWT", async () => {
      expect.assertions(7);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZTokenDidKey();

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          hexPrivateKey,
          did,
          kid: `#${did.substring(8)}`,
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
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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
          `#${did.substring(8)}`
        ),
      };

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });

    it("create did Auth request payload without sign it", async () => {
      expect.assertions(8);
      const { did, hexPublicKey } = await getUserEntityTestAuthZToken();

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          hexPublicKey,
          did,
          kid: `#${did.substring(8)}`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const payload = await siopDidAuth.createDidAuthRequestObject(opts);
      expect(payload).toBeDefined();
      expect(payload.iss).toStrictEqual(did);
      expect(payload.client_id).toStrictEqual("http://app.example/demo");
      expect(payload).toHaveProperty("scope");
      expect(payload).toHaveProperty("registration");
      expect(payload).toHaveProperty("nonce");
      expect(payload).toHaveProperty("state");
      expect(payload).toHaveProperty("response_type");
    });

    it("create did Auth request payload without sign it for did keys", async () => {
      expect.assertions(8);
      const { did, hexPublicKey } = await getUserEntityTestAuthZTokenDidKey();

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://app.example/demo",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          hexPublicKey,
          did,
          kid: `#${did.substring(8)}`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
      };

      const payload = await siopDidAuth.createDidAuthRequestObject(opts);

      expect(payload).toBeDefined();
      expect(payload.iss).toStrictEqual(did);
      expect(payload.client_id).toStrictEqual("http://app.example/demo");
      expect(payload).toHaveProperty("scope");
      expect(payload).toHaveProperty("registration");
      expect(payload).toHaveProperty("nonce");
      expect(payload).toHaveProperty("state");
      expect(payload).toHaveProperty("response_type");
    });
  });
  describe("create Uri Response tests with", () => {
    it("an id_token and state using the default response_mode=fragment with only required params", async () => {
      expect.assertions(10);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZTokenDidKey();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `#${did.substring(8)}`,
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
      const urlDecoded = decodeURI(uriResponse.urlEncoded);
      expect(urlDecoded).toContain(`https://app.example/demo`);
      const splitUrl = urlDecoded.split("#");
      const data = parse(splitUrl[1]);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
    it("an id_token and state using response_mode=query with only required params", async () => {
      expect.assertions(10);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZTokenDidKey();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `#${did.substring(8)}`,
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
      const urlDecoded = decodeURI(uriResponse.urlEncoded);
      expect(urlDecoded).toContain(`https://app.example/demo`);
      const splitUrl = urlDecoded.split("?");
      const data = parse(splitUrl[1]);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
    it("an id_token and state using response_mode=form_post with only required params", async () => {
      expect.assertions(11);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZTokenDidKey();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `#${did.substring(8)}`,
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
      expect(decodeURI(uriResponse.urlEncoded)).toContain(
        `https://app.example/demo`
      );
      const urlDecoded = decodeURI(uriResponse.bodyEncoded);
      const data = parse(urlDecoded);
      expect(data.id_token).toBeDefined();
      expect(data.state).toBeDefined();
      expect(data.state).toStrictEqual(state);
    });
  });
  describe("verifyDidAuthResponse tests should", () => {
    it("verify internally a DidAuth Response JWT", async () => {
      expect.assertions(7);
      const { hexPrivateKey, did } = await getUserEntityTestAuthZTokenDidKey();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const kid = await getKidFromDID(did);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid,
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
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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
      expectedPayload.sub_jwk = DidAuthJwk.getPublicJWKFromPrivateHexDidKey(
        hexPrivateKey,
        kid
      );

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });

    it("verify externally a DidAuth Response JWT generated internally", async () => {
      expect.assertions(7);
      const entityAA = await getLegalEntityTestAuthZToken(
        "LEGAL ENTITY TEST 007"
      );
      const authZToken = entityAA.jwt;
      const { hexPrivateKey, did } = await getUserEntityTestAuthZTokenDidKey();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const kid = await getKidFromDID(did);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid,
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
          verifyUri: `https://dev.vidchain.net/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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
      expectedPayload.sub_jwk = DidAuthJwk.getPublicJWKFromPrivateHexDidKey(
        hexPrivateKey,
        kid
      );
      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
    });

    it("verify externally a DidAuth Response JWT generated externally with a test entity", async () => {
      expect.assertions(7);
      const entityAA = await getLegalEntityTestAuthZToken(
        "LEGAL ENTITY TEST 007"
      );
      const authZToken = entityAA.jwt;
      const { did } = entityAA;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          signatureUri: `https://dev.vidchain.net/api/v1/signatures`,
          did,
          authZToken,
          kid: `#${did.substring(8)}`,
        },
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${did};transform-keys=jwks`,
        },
        did,
      };

      const jwt = await siopDidAuth.createDidAuthResponse(opts);
      expect(jwt).toBeDefined();

      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `https://dev.vidchain.net/api/v1/signature-validations`,
          authZToken,
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
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

  describe("createDidAuthResponseObject", () => {
    it("should create Did Auth Response Object without signature", async () => {
      expect.assertions(7);
      const { did, hexPrivateKey } = await getUserEntityTestAuthZToken();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOptsNoSignature = {
        redirectUri: "https://app.example/demo",
        identifiersUri: `https://dev.vidchain.net/api/v1/identifiers/${did};transform-keys=jwks`,
        nonce,
        state,
        responseMode: DidAuthResponseMode.FORM_POST,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const jwt: siopDidAuth.DidAuthTypes.DidAuthResponsePayload =
        await siopDidAuth.createDidAuthResponseObject(opts);
      expect(jwt).toBeDefined();

      const signedToken = await signDidAuthInternal(
        jwt,
        DidAuthResponseIss.SELF_ISSUE,
        hexPrivateKey
      );

      const optsVerify: DidAuthVerifyOpts = {
        verificationType: {
          registry: process.env.DID_REGISTRY_SC_ADDRESS,
          rpcUrl: process.env.DID_PROVIDER_RPC_URL,
          didUrlResolver: `https://dev.vidchain.net/api/v1/identifiers`,
        },
        nonce,
        redirectUri: opts.redirectUri,
      };
      const validationResponse = await verifyDidAuthResponse(
        signedToken,
        optsVerify
      );
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
    it("should validate a new VIDwallet id_token", async () => {
      const jwt =
        "eyJraWQiOiJkaWQ6ZXRocjoweDlmMTVBNTFhMzc0NDU1ZDNkNjM3RGEwYzc0MDU5REE4Mzk5ZDVlQTciLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2ODc3OTQxMTIsInJlZGlyZWN0VXJpIjoiaHR0cHM6Ly9kZXYudmlkY2hhaW4ubmV0L3Npb3AvcmVzcG9uc2VzIiwiaWRlbnRpZmllcnNVcmkiOiJodHRwczovL2Rldi52aWRjaGFpbi5uZXQvd2FsbGV0LWFwaS92MS9yZXNvbHZlciIsIm5vbmNlIjoiZm9hRzRGbFNwNGlpT1Znb2o5TWtEWVRjLTNVMEVwQjE2clQwcENVVXozUSIsInN0YXRlIjoiN2VmZGRlOTE2NjA0ZGI0MmM4YmZlMGVkIiwiYXVkIjoiaHR0cHM6Ly9kZXYudmlkY2hhaW4ubmV0L3Npb3AvcmVzcG9uc2VzIiwicmVzcG9uc2VNb2RlIjoiZnJhZ21lbnQiLCJyZWdpc3RyYXRpb25UeXBlIjp7InR5cGUiOiJWQUxVRSJ9LCJkaWQiOiJkaWQ6ZXRocjoweDlmMTVBNTFhMzc0NDU1ZDNkNjM3RGEwYzc0MDU5REE4Mzk5ZDVlQTciLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvZGlkL3YxIl0sInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImlkIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9jcmVkZW50aWFsLzIzOTAiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUlkIl0sImlzc3VlciI6eyJpZCI6ImRpZDpldGhyOjB4M2UxMTVFODY3YTAzMUU1MTYwODkwQjRmMjBGRTMwRTM5YUMwYjEzNyIsIm5hbWUiOiJlbnRpdGF0U3dhZ2dlciJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9zdGFnaW5nLnZpZGNoYWluLm5ldC9hcGkvdjEvcmV2b2NhdGlvbi9jcmVkZW50aWFsLXN0YXR1cy9zdGF0dXMtbGlzdC81L2NyZWRlbnRpYWwvNDkiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vc3RhZ2luZy52aWRjaGFpbi5uZXQvYXBpL3YxL3Jldm9jYXRpb24vc3RhdHVzLWxpc3QvNSIsInN0YXR1c0xpc3RJbmRleCI6IjQ5IiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMSJ9LCJpc3N1YW5jZURhdGUiOiIyMDIzLTA1LTE4VDE0OjA4OjEyLjAwMFoiLCJ2YWxpZFVudGlsIjoiMjAzMC0wMS0wMVQyMToxOToxMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJiaXJ0aE5hbWUiOiJFdmEiLCJjdXJyZW50QWRkcmVzcyI6IjQ0LCBydWUgZGUgRmFtZSIsImN1cnJlbnRGYW1pbHlOYW1lIjoiRXZhIiwiY3VycmVudEdpdmVuTmFtZSI6IkFkYW1zIiwiZGF0ZU9mQmlydGgiOiIxOTk4LTAyLTE0IiwiZ2VuZGVyIjoiRmVtYWxlIiwiaWQiOiJkaWQ6ZXRocjoweDlmMTVBNTFhMzc0NDU1ZDNkNjM3RGEwYzc0MDU5REE4Mzk5ZDVlQTciLCJwZXJzb25JZGVudGlmaWVyIjoiQkUvQkUvMDI2MzU1NDJZIiwicGxhY2VPZkJpcnRoIjoiQnJ1c3NlbHMifSwicHJvb2YiOnsidHlwZSI6IkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsImNyZWF0ZWQiOiIyMDIzLTA1LTE4VDE0OjA4OjEyLjAwMFoiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXRocjoweERmQkE3RTdENmZkOUQzQjVCOTAwY0UyYWEzZDlFNmFBNDM1NzRGQzAja2V5cy0xIiwiandzIjoiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2WlhSb2Nqb3dlRVJtUWtFM1JUZEVObVprT1VRelFqVkNPVEF3WTBVeVlXRXpaRGxGTm1GQk5ETTFOelJHUXpBamEyVjVjeTB4SWl3aWRIbHdJam9pU2xkVUluMC5leUpwWVhRaU9qRTJPRFEwTVRnNE9USXNJbWx6Y3lJNkltUnBaRHBsZEdoeU9qQjRSR1pDUVRkRk4wUTJabVE1UkROQ05VSTVNREJqUlRKaFlUTmtPVVUyWVVFME16VTNORVpETUNJc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VGRHRjBkWE1pT25zaWFXUWlPaUpvZEhSd2N6b3ZMM04wWVdkcGJtY3VkbWxrWTJoaGFXNHVibVYwTDJGd2FTOTJNUzl5WlhadlkyRjBhVzl1TDJOeVpXUmxiblJwWVd3dGMzUmhkSFZ6TDNOMFlYUjFjeTFzYVhOMEx6VXZZM0psWkdWdWRHbGhiQzgwT1NJc0luTjBZWFIxYzB4cGMzUkRjbVZrWlc1MGFXRnNJam9pYUhSMGNITTZMeTl6ZEdGbmFXNW5MblpwWkdOb1lXbHVMbTVsZEM5aGNHa3ZkakV2Y21WMmIyTmhkR2x2Ymk5emRHRjBkWE10YkdsemRDODFJaXdpYzNSaGRIVnpUR2x6ZEVsdVpHVjRJam9pTkRraUxDSjBlWEJsSWpvaVVtVjJiMk5oZEdsdmJreHBjM1F5TURJeEluMHNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SW1KcGNuUm9UbUZ0WlNJNklrVjJZU0lzSW1OMWNuSmxiblJCWkdSeVpYTnpJam9pTkRRc0lISjFaU0JrWlNCR1lXMWxJaXdpWTNWeWNtVnVkRVpoYldsc2VVNWhiV1VpT2lKRmRtRWlMQ0pqZFhKeVpXNTBSMmwyWlc1T1lXMWxJam9pUVdSaGJYTWlMQ0prWVhSbFQyWkNhWEowYUNJNklqRTVPVGd0TURJdE1UUWlMQ0puWlc1a1pYSWlPaUpHWlcxaGJHVWlMQ0pwWkNJNkltUnBaRHBsZEdoeU9qQjRNa0ppTVRZeU9VUmpNV1k1T1RKRk1EQmhPVVV4TnpBME5qUkNSVE00TURKaVlUSTFPVUl6UlNJc0luQmxjbk52Ymtsa1pXNTBhV1pwWlhJaU9pSkNSUzlDUlM4d01qWXpOVFUwTWxraUxDSndiR0ZqWlU5bVFtbHlkR2dpT2lKQ2NuVnpjMlZzY3lKOUxDSnBaQ0k2SW1oMGRIQnpPaTh2WlhoaGJYQnNaUzVqYjIwdlkzSmxaR1Z1ZEdsaGJDOHlNemt3SWl3aWFYTnpkV1Z5SWpwN0ltbGtJam9pWkdsa09tVjBhSEk2TUhoRVprSkJOMFUzUkRabVpEbEVNMEkxUWprd01HTkZNbUZoTTJRNVJUWmhRVFF6TlRjMFJrTXdJaXdpYm1GdFpTSTZJbVZ1ZEdsMFlYUlRkMkZuWjJWeUluMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKV1pYSnBabWxoWW14bFNXUWlYU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNekF0TURFdE1ERlVNakU2TVRrNk1UQmFJbjE5LlRFSEVZemZ0RWdFQ2FhV1I5LTVQNmVXb2pCc0VZbEJQeHprRTNiSXltU050c0p1cFVDdlZVS0pOV3NHcWQzbC15cEFzalZnUzFCMGkyUWowVFc5V3ZRIn19XSwicHJvb2YiOnsidHlwZSI6IkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDpldGhyOjB4OWYxNUE1MWEzNzQ0NTVkM2Q2MzdEYTBjNzQwNTlEQTgzOTlkNWVBNyNrZXktMSIsImNyZWF0ZWQiOiIyMDIzLTA2LTI2VDE1OjQxOjUyLjQxMVoiLCJqd3MiOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUpwWVhRaU9qRTJPRGMzT1RReE1USXNJbWx6Y3lJNkltUnBaRHBsZEdoeU9qQjRPV1l4TlVFMU1XRXpOelEwTlRWa00yUTJNemRFWVRCak56UXdOVGxFUVRnek9UbGtOV1ZCTnlJc0luWndJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OXVjeTlrYVdRdmRqRWlYU3dpZEhsd1pTSTZJbFpsY21sbWFXRmliR1ZRY21WelpXNTBZWFJwYjI0aUxDSjJaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0k2VzNzaVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWFXUWlPaUpvZEhSd2N6b3ZMMlY0WVcxd2JHVXVZMjl0TDJOeVpXUmxiblJwWVd3dk1qTTVNQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSldaWEpwWm1saFlteGxTV1FpWFN3aWFYTnpkV1Z5SWpwN0ltbGtJam9pWkdsa09tVjBhSEk2TUhnelpURXhOVVU0TmpkaE1ETXhSVFV4TmpBNE9UQkNOR1l5TUVaRk16QkZNemxoUXpCaU1UTTNJaXdpYm1GdFpTSTZJbVZ1ZEdsMFlYUlRkMkZuWjJWeUluMHNJbU55WldSbGJuUnBZV3hUZEdGMGRYTWlPbnNpYVdRaU9pSm9kSFJ3Y3pvdkwzTjBZV2RwYm1jdWRtbGtZMmhoYVc0dWJtVjBMMkZ3YVM5Mk1TOXlaWFp2WTJGMGFXOXVMMk55WldSbGJuUnBZV3d0YzNSaGRIVnpMM04wWVhSMWN5MXNhWE4wTHpVdlkzSmxaR1Z1ZEdsaGJDODBPU0lzSW5OMFlYUjFjMHhwYzNSRGNtVmtaVzUwYVdGc0lqb2lhSFIwY0hNNkx5OXpkR0ZuYVc1bkxuWnBaR05vWVdsdUxtNWxkQzloY0drdmRqRXZjbVYyYjJOaGRHbHZiaTl6ZEdGMGRYTXRiR2x6ZEM4MUlpd2ljM1JoZEhWelRHbHpkRWx1WkdWNElqb2lORGtpTENKMGVYQmxJam9pVW1WMmIyTmhkR2x2Ymt4cGMzUXlNREl4SW4wc0ltbHpjM1ZoYm1ObFJHRjBaU0k2SWpJd01qTXRNRFV0TVRoVU1UUTZNRGc2TVRJdU1EQXdXaUlzSW5aaGJHbGtWVzUwYVd3aU9pSXlNRE13TFRBeExUQXhWREl4T2pFNU9qRXdXaUlzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltSnBjblJvVG1GdFpTSTZJa1YyWVNJc0ltTjFjbkpsYm5SQlpHUnlaWE56SWpvaU5EUXNJSEoxWlNCa1pTQkdZVzFsSWl3aVkzVnljbVZ1ZEVaaGJXbHNlVTVoYldVaU9pSkZkbUVpTENKamRYSnlaVzUwUjJsMlpXNU9ZVzFsSWpvaVFXUmhiWE1pTENKa1lYUmxUMlpDYVhKMGFDSTZJakU1T1RndE1ESXRNVFFpTENKblpXNWtaWElpT2lKR1pXMWhiR1VpTENKcFpDSTZJbVJwWkRwbGRHaHlPakI0T1dZeE5VRTFNV0V6TnpRME5UVmtNMlEyTXpkRVlUQmpOelF3TlRsRVFUZ3pPVGxrTldWQk55SXNJbkJsY25OdmJrbGtaVzUwYVdacFpYSWlPaUpDUlM5Q1JTOHdNall6TlRVME1sa2lMQ0p3YkdGalpVOW1RbWx5ZEdnaU9pSkNjblZ6YzJWc2N5SjlMQ0p3Y205dlppSTZleUowZVhCbElqb2lSV05rYzJGVFpXTndNalUyYXpGVGFXZHVZWFIxY21VeU1ERTVJaXdpWTNKbFlYUmxaQ0k2SWpJd01qTXRNRFV0TVRoVU1UUTZNRGc2TVRJdU1EQXdXaUlzSW5CeWIyOW1VSFZ5Y0c5elpTSTZJbUZ6YzJWeWRHbHZiazFsZEdodlpDSXNJblpsY21sbWFXTmhkR2x2YmsxbGRHaHZaQ0k2SW1ScFpEcGxkR2h5T2pCNFJHWkNRVGRGTjBRMlptUTVSRE5DTlVJNU1EQmpSVEpoWVROa09VVTJZVUUwTXpVM05FWkRNQ05yWlhsekxURWlMQ0pxZDNNaU9pSmxlVXBvWWtkamFVOXBTa1pWZWtreFRtdHphVXhEU25KaFYxRnBUMmxLYTJGWFVUWmFXRkp2WTJwdmQyVkZVbTFSYTBVelVsUmtSVTV0V210UFZWRjZVV3BXUTA5VVFYZFpNRlY1V1ZkRmVscEViRVpPYlVaQ1RrUk5NVTU2VWtkUmVrRnFZVEpXTldONU1IaEphWGRwWkVoc2QwbHFiMmxUYkdSVlNXNHdMbVY1U25CWldGRnBUMnBGTWs5RVVUQk5WR2MwVDFSSmMwbHRiSHBqZVVrMlNXMVNjRnBFY0d4a1IyaDVUMnBDTkZKSFdrTlJWR1JHVGpCUk1scHRVVFZTUkU1RFRsVkpOVTFFUW1wU1ZFcG9XVlJPYTA5VlZUSlpWVVV3VFhwVk0wNUZXa1JOUTBselNXNWFha2xxY0RkSmEwSnFZakkxTUZwWWFEQkphbkJpU1cxb01HUklRbnBQYVRoMlpETmtNMHh1WTNwTWJUbDVXbms0ZVUxRVJUUk1NazU1V2xkU2JHSnVVbkJaVjNoNlRETlplRWxzTUhOSmJVNTVXbGRTYkdKdVVuQlpWM2hVWkVkR01HUllUV2xQYm5OcFlWZFJhVTlwU205a1NGSjNZM3B2ZGt3elRqQlpWMlJ3WW0xamRXUnRiR3RaTW1ob1lWYzBkV0p0VmpCTU1rWjNZVk01TWsxVE9YbGFXRnAyV1RKR01HRlhPWFZNTWs1NVdsZFNiR0p1VW5CWlYzZDBZek5TYUdSSVZucE1NMDR3V1ZoU01XTjVNWE5oV0U0d1RIcFZkbGt6U214YVIxWjFaRWRzYUdKRE9EQlBVMGx6U1c1T01GbFlVakZqTUhod1l6TlNSR050Vm10YVZ6VXdZVmRHYzBscWIybGhTRkl3WTBoTk5reDVPWHBrUjBadVlWYzFia3h1V25CYVIwNXZXVmRzZFV4dE5XeGtRemxvWTBkcmRtUnFSWFpqYlZZeVlqSk9hR1JIYkhaaWFUbDZaRWRHTUdSWVRYUmlSMng2WkVNNE1VbHBkMmxqTTFKb1pFaFdlbFJIYkhwa1JXeDFXa2RXTkVscWIybE9SR3RwVEVOS01HVllRbXhKYW05cFZXMVdNbUl5VG1oa1IyeDJZbXQ0Y0dNelVYbE5SRWw0U1c0d2MwbHRUbmxhVjFKc1ltNVNjRmxYZUZSa1YwcHhXbGRPTUVscWNEZEpiVXB3WTI1U2IxUnRSblJhVTBrMlNXdFdNbGxUU1hOSmJVNHhZMjVLYkdKdVVrSmFSMUo1V2xoT2VrbHFiMmxPUkZGelNVaEtNVnBUUW10YVUwSkhXVmN4YkVscGQybFpNMVo1WTIxV2RXUkZXbWhpVjJ4elpWVTFhR0pYVldsUGFVcEdaRzFGYVV4RFNtcGtXRXA1V2xjMU1GSXliREphVnpWUFdWY3hiRWxxYjJsUlYxSm9ZbGhOYVV4RFNtdFpXRkpzVkRKYVEyRllTakJoUTBrMlNXcEZOVTlVWjNSTlJFbDBUVlJSYVV4RFNtNWFWelZyV2xoSmFVOXBTa2RhVnpGb1lrZFZhVXhEU25CYVEwazJTVzFTY0ZwRWNHeGtSMmg1VDJwQ05FMXJTbWxOVkZsNVQxVlNhazFYV1RWUFZFcEdUVVJDYUU5VlZYaE9la0V3VG1wU1ExSlVUVFJOUkVwcFdWUkpNVTlWU1hwU1UwbHpTVzVDYkdOdVRuWmlhMnhyV2xjMU1HRlhXbkJhV0VscFQybEtRMUpUT1VOU1V6aDNUV3BaZWs1VVZUQk5iR3RwVEVOS2QySkhSbXBhVlRsdFVXMXNlV1JIWjJsUGFVcERZMjVXZW1NeVZuTmplVW81VEVOS2NGcERTVFpKYldnd1pFaENlazlwT0haYVdHaG9ZbGhDYzFwVE5XcGlNakIyV1ROS2JGcEhWblZrUjJ4b1lrTTRlVTE2YTNkSmFYZHBZVmhPZW1SWFZubEphbkEzU1cxc2EwbHFiMmxhUjJ4clQyMVdNR0ZJU1RaTlNHaEZXbXRLUWs0d1ZUTlNSRnB0V2tSc1JVMHdTVEZSYW10M1RVZE9SazF0Um1oTk1sRTFVbFJhYUZGVVVYcE9WR013VW10TmQwbHBkMmxpYlVaMFdsTkpOa2x0Vm5Wa1Iyd3dXVmhTVkdReVJtNWFNbFo1U1c0d2MwbHVValZqUjFWcFQyeHphVlp0Vm5saFYxcHdXVmRLYzFwVlRubGFWMUpzWW01U2NGbFhkMmxNUTBwWFdsaEtjRnB0YkdoWmJYaHNVMWRSYVZoVGQybGtiVVp6WVZkU1ZtSnVVbkJpUTBrMlNXcEpkMDE2UVhSTlJFVjBUVVJHVlUxcVJUWk5WR3MyVFZSQ1lVbHVNVGt1VkVWSVJWbDZablJGWjBWRFlXRlhVamt0TlZBMlpWZHZha0p6UlZsc1FsQjRlbXRGTTJKSmVXMVRUblJ6U25Wd1ZVTjJWbFZMU2s1WGMwZHhaRE5zTFhsd1FYTnFWbWRUTVVJd2FUSlJhakJVVnpsWGRsRWlmWDFkZlgwLnkxaHc2NWZDdzRVc20zd1F6a05aMnAtSjZIZUcxMENNVFdEZXB1bFd4OHk0TXlJeURSZXJaa0ZuOE1TbjcweUpvYVZsM25PUVFoYll0MUc1a2FqeXl3In19LCJpc3MiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lIn0.E5njI5_tBvYa50aTCsV9tP0syNvbDCdE5NwMdIo8WBCfJq6975GE19M7XYI8g2HixGSWBd5cdceGSnajAwNoow";
      const { payload } = decodeJWT(jwt);

      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        nonce: payload.nonce as string,
        redirectUri: payload.redirectUri as string,
        verificationType: {
          didUrlResolver: payload.identifiersUri as string,
        },
      };
      const validationResponse = await verifyDidAuthResponse(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
    });
  });
});
