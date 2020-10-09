import * as dotenv from "dotenv";

import { decodeJWT } from "did-jwt";
import {
  DIDAUTH_HEADER,
  DIDAUTH_REQUEST_PAYLOAD,
  DIDAUTH_RESPONSE_PAYLOAD,
  getEnterpriseAuthZToken,
  generateTestKey,
} from "./AuxTest";
import {
  getHexPrivateKey,
  DIAUTHScope,
  DIAUTHResponseType,
  DIDAUTH_RESPONSE_ISS,
  EbsiDidAuth,
  DidAuthRequestCall,
  DidAuthRequestPayload,
  getNonce,
  DIDAUTH_KEY_TYPE,
  DidAuthResponseCall,
} from "../src";

// importing .env variables
dotenv.config();

jest.setTimeout(10000);

describe("ebsiDidAuth", () => {
  describe("eBSI DID Auth Request", () => {
    it("should create a DID Auth Request URL with a JWT embedded", async () => {
      expect.assertions(5);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };

      const { uri, nonce } = await EbsiDidAuth.createUriRequest(
        didAuthRequestCall
      );
      expect(uri).toContain(`openid://&scope=${DIAUTHScope.OPENID_DIDAUTHN}`);
      expect(uri).toContain(`?response_type=${DIAUTHResponseType.ID_TOKEN}`);
      expect(uri).toContain(`&client_id=${didAuthRequestCall.redirectUri}`);
      expect(uri).toContain("&request=");
      expect(nonce).toBeDefined();
      jest.clearAllMocks();
    });

    it('should create a JWT DID Auth Request token with "ES256K-R" algo using wallet keys from a random Enterprise', async () => {
      expect.assertions(5);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };

      const { jwt, nonce } = await EbsiDidAuth.createDidAuthRequest(
        didAuthRequestCall
      );
      expect(nonce).toBeDefined();
      const { header, payload } = decodeJWT(jwt);

      const expectedHeader = DIDAUTH_HEADER;
      expectedHeader.kid = `${didEntityAA}#key-1`;
      const expectedPayload = DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = didEntityAA;
      expectedPayload.nonce = expect.any(String);
      expectedPayload.client_id = didAuthRequestCall.redirectUri;
      expectedPayload.iat = expect.any(Number);
      expectedPayload.exp = expect.any(Number);

      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual((payload.iat as number) + 5 * 60); // 5 minutes of expiration time
      jest.clearAllMocks();
    });

    it("should return a valid payload on DID Auth request validation", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
      const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };

      const { jwt } = await EbsiDidAuth.createDidAuthRequest(
        didAuthRequestCall
      );
      const payload: DidAuthRequestPayload = await EbsiDidAuth.verifyDidAuthRequest(
        jwt,
        RPC_ADDRESS,
        RPC_PROVIDER
      );

      const expectedPayload = DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = didEntityAA;
      expectedPayload.nonce = expect.any(String);
      expectedPayload.client_id = didAuthRequestCall.redirectUri;
      expectedPayload.iat = expect.any(Number);
      expectedPayload.exp = expect.any(Number);

      expect((payload as DidAuthRequestPayload).iat).toBeDefined();
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(
        ((payload as DidAuthRequestPayload).iat as number) + 5 * 60
      ); // 5 minutes of expiration time
      jest.clearAllMocks();
    });
  });

  describe("eBSI DID Auth Response", () => {
    it('should create a JWT DID Auth Response token with "ES256K-R" algo and random keys generated', async () => {
      expect.assertions(4);
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DIDAUTH_KEY_TYPE.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };
      const didAuthJwt = await EbsiDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      const { header, payload } = decodeJWT(didAuthJwt);

      const expectedHeader = DIDAUTH_HEADER;
      expectedHeader.kid = `${testKeyUser.did}#key-1`;
      const expectedPayload = DIDAUTH_RESPONSE_PAYLOAD;
      expectedPayload.iss = expect.stringMatching(
        DIDAUTH_RESPONSE_ISS.SELF_ISSUE
      );
      expectedPayload.aud = didAuthResponseCall.redirectUri;
      expectedPayload.nonce = expect.any(String);
      expectedPayload.iat = expect.any(Number);
      expectedPayload.exp = expect.any(Number);
      expectedPayload.sub_jwk.kid = expect.stringContaining("did:ebsi:");
      expectedPayload.sub_jwk.x = expect.any(String);
      expectedPayload.sub_jwk.y = expect.any(String);
      expectedPayload.sub = expect.any(String);

      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual((payload.iat as number) + 5 * 60); // 5 minutes of expiration time
      jest.clearAllMocks();
    });

    it("should return valid payload on DID Auth Response validation", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await getEnterpriseAuthZToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DIDAUTH_KEY_TYPE.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };

      const didAuthJwt = await EbsiDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      const response = await EbsiDidAuth.verifyDidAuthResponse(
        didAuthJwt,
        `${WALLET_API_BASE_URL}/wallet/v1/signature-validations`,
        tokenEntityAA,
        requestDIDAuthNonce
      );
      expect(response).toBeDefined();
      expect(response).toHaveProperty("signatureValidation");
      expect(response.signatureValidation).toBe(true);
    });
  });
});
