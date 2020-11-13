import * as dotenv from "dotenv";

import { decodeJWT } from "did-jwt";
import { getEnterpriseAuthZToken, generateTestKey } from "../AuxTest";
import {
  getHexPrivateKey,
  DidAuthScope,
  DidAuthResponseType,
  DidAuthResponseIss,
  VidDidAuth,
  DidAuthRequestCall,
  DidAuthRequestPayload,
  getNonce,
  DidAuthKeyType,
  DidAuthResponseCall,
} from "../../src";
import * as mockedData from "../data/mockedData";

// importing .env variables
dotenv.config();

jest.setTimeout(10000);

describe("vidDidAuth", () => {
  describe("vid DID Auth Request", () => {
    it("should create a DID Auth Request URL with a JWT as reference", async () => {
      expect.assertions(6);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        requestUri: "https://dev.vidchain.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV",
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        authZToken: tokenEntityAA,
      };

      const { uri, nonce } = await VidDidAuth.createUriRequest(
        didAuthRequestCall
      );
      expect(uri).toContain(`openid://`);
      expect(uri).toContain(`?response_type=${DidAuthResponseType.ID_TOKEN}`);
      expect(uri).toContain(`&client_id=${didAuthRequestCall.redirectUri}`);
      expect(uri).toContain(`&scope=${DidAuthScope.OPENID_DIDAUTHN}`);
      expect(uri).toContain(`&requestUri=${didAuthRequestCall.requestUri}`);
      expect(nonce).toBeDefined();
    });

    it('should create a JWT DID Auth Request token with "ES256K-R" algo using wallet keys from a random Enterprise', async () => {
      expect.assertions(5);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        requestUri: "https://dev.vidchain.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV",
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        authZToken: tokenEntityAA,
      };

      const { jwt, nonce } = await VidDidAuth.createDidAuthRequest(
        didAuthRequestCall
      );
      expect(nonce).toBeDefined();
      const { header, payload } = decodeJWT(jwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${didEntityAA}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = didEntityAA;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.client_id = didAuthRequestCall.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;

      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60); // 5 minutes of expiration time
    });

    it("should create a JWT DID Auth Request token with vc claims", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        requestUri: "https://dev.vidchain.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV",
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        authZToken: tokenEntityAA,
        claims: mockedData.verifiableIdOidcClaim,
      };

      const { jwt, nonce } = await VidDidAuth.createDidAuthRequest(
        didAuthRequestCall
      );
      expect(nonce).toBeDefined();
      const { header, payload } = decodeJWT(jwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${didEntityAA}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD_CLAIMS;
      expectedPayload.iss = didEntityAA;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.client_id = didAuthRequestCall.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;

      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
    });

    it("should return a valid payload on DID Auth request validation", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const RPC_PROVIDER = process.env.DID_PROVIDER_RPC_URL;
      const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        requestUri: "https://dev.vidchain.net/siop/jwts/N7A8u4VmZfMGGdAtAAFV",
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        authZToken: tokenEntityAA,
      };

      const { jwt } = await VidDidAuth.createDidAuthRequest(didAuthRequestCall);
      const payload: DidAuthRequestPayload = await VidDidAuth.verifyDidAuthRequest(
        jwt,
        RPC_ADDRESS,
        RPC_PROVIDER
      );

      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = didEntityAA;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.client_id = didAuthRequestCall.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;

      expect(payload.iat).toBeDefined();
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60); // 5 minutes of expiration time
    });
  });

  describe("vid DID Auth Response", () => {
    it('should create a JWT DID Auth Response token with "ES256K-R" algo and random keys generated', async () => {
      expect.assertions(4);
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DidAuthKeyType.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };
      const didAuthJwt = await VidDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      const { header, payload } = decodeJWT(didAuthJwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${testKeyUser.did}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD;
      expectedPayload.iss = expect.stringMatching(
        DidAuthResponseIss.SELF_ISSUE
      ) as string;
      expectedPayload.aud = didAuthResponseCall.redirectUri;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.sub_jwk.kid = expect.stringContaining(
        "did:vid:"
      ) as string;
      expectedPayload.sub_jwk.x = expect.any(String) as string;
      expectedPayload.sub_jwk.y = expect.any(String) as string;
      expectedPayload.sub = expect.any(String) as string;

      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60); // 5 minutes of expiration time
    });

    it("should create a JWT DID Auth Response token with Verifiable Presentation", async () => {
      expect.assertions(2);
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DidAuthKeyType.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
        vp: mockedData.verifiableIdPresentation,
      };
      const didAuthJwt = await VidDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      const { header, payload } = decodeJWT(didAuthJwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${testKeyUser.did}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD_VP;
      expectedPayload.iss = expect.stringMatching(
        DidAuthResponseIss.SELF_ISSUE
      ) as string;
      expectedPayload.aud = didAuthResponseCall.redirectUri;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.sub_jwk.kid = expect.stringContaining(
        "did:vid:"
      ) as string;
      expectedPayload.sub_jwk.x = expect.any(String) as string;
      expectedPayload.sub_jwk.y = expect.any(String) as string;
      expectedPayload.sub = expect.any(String) as string;

      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
    });

    it("should return valid payload on DID Auth Response validation", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DidAuthKeyType.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };

      const didAuthJwt = await VidDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      const response = await VidDidAuth.verifyDidAuthResponse(
        didAuthJwt,
        `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        tokenEntityAA,
        requestDIDAuthNonce
      );
      expect(response).toBeDefined();
      expect(response).toHaveProperty("signatureValidation");
      expect(response.signatureValidation).toBe(true);
    });
  });
});
