import * as dotenv from "dotenv";
import axios from "axios";
import * as didJwt from "did-jwt";
import { JWT } from "jose";
import {
  DIDAUTH_HEADER,
  DIDAUTH_REQUEST_PAYLOAD,
  DIDAUTH_RESPONSE_PAYLOAD,
  mockedGetEnterpriseAuthToken,
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
  DIDAUTH_KEY_ALGO,
  JWTHeader,
  DIDAUTH_ERRORS,
} from "../src";

// importing .env variables
dotenv.config();

jest.setTimeout(10000);

describe("ebsiDidAuth", () => {
  describe("eBSI DID Auth Request", () => {
    it("should throw BAD_PARAMS when no client_id is present", async () => {
      expect.assertions(1);

      const didAuthRequestCall = {
        signatureUri: "",
        authZToken: "",
      };

      await expect(
        EbsiDidAuth.createUriRequest(didAuthRequestCall as any)
      ).rejects.toThrow(DIDAUTH_ERRORS.BAD_PARAMS);
    });

    it("should throw BAD_PARAMS when no params is passed", async () => {
      expect.assertions(1);

      await expect(
        EbsiDidAuth.createUriRequest(undefined as any)
      ).rejects.toThrow(DIDAUTH_ERRORS.BAD_PARAMS);
    });

    it("should create a DID Auth Request URL with a JWT embedded", async () => {
      expect.assertions(5);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DIDAUTH_KEY_ALGO.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const payload = {
          iss: entityAA.did,
          scope: DIAUTHScope.OPENID_DIDAUTHN,
          response_type: DIAUTHResponseType.ID_TOKEN,
          client_id: didAuthRequestCall.redirectUri,
          nonce: getNonce(),
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DIDAUTH_KEY_ALGO.ES256KR,
            signer: didJwt.SimpleSigner(
              getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ), // Removing 0x from private key as input of SimpleSigner
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

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

    it("should throw MALFORMED_SIGNATURE_RESPONSE", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        return {
          status: 400,
          data: { jws: undefined },
        };
      });

      await expect(
        EbsiDidAuth.createDidAuthRequest(didAuthRequestCall)
      ).rejects.toThrow(DIDAUTH_ERRORS.MALFORMED_SIGNATURE_RESPONSE);
      jest.clearAllMocks();
    });

    it("should throw BAD_PARAMS", async () => {
      expect.assertions(1);
      const didAuthRequestCall = {
        signatureUri: "",
        authZToken: "",
      };
      await expect(
        EbsiDidAuth.createDidAuthRequest(didAuthRequestCall as any)
      ).rejects.toThrow(DIDAUTH_ERRORS.BAD_PARAMS);
      jest.clearAllMocks();
    });

    it("should throw KEY_SIGNATURE_URI_ERROR", async () => {
      expect.assertions(1);
      const didAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        authZToken: "",
      };
      await expect(
        EbsiDidAuth.createDidAuthRequest(didAuthRequestCall as any)
      ).rejects.toThrow(DIDAUTH_ERRORS.KEY_SIGNATURE_URI_ERROR);
      jest.clearAllMocks();
    });

    it("should throw AUTHZTOKEN_UNDEFINED", async () => {
      expect.assertions(1);
      const didAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `/wallet/v1/signatures`,
      };
      await expect(
        EbsiDidAuth.createDidAuthRequest(didAuthRequestCall as any)
      ).rejects.toThrow(DIDAUTH_ERRORS.AUTHZTOKEN_UNDEFINED);
      jest.clearAllMocks();
    });

    it('should create a JWT DID Auth Request token with "ES256K-R" algo using wallet keys from a random Enterprise', async () => {
      expect.assertions(5);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DIDAUTH_KEY_ALGO.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const payload = {
          iss: entityAA.did,
          scope: DIAUTHScope.OPENID_DIDAUTHN,
          response_type: DIAUTHResponseType.ID_TOKEN,
          client_id: didAuthRequestCall.redirectUri,
          nonce: getNonce(),
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DIDAUTH_KEY_ALGO.ES256KR,
            signer: didJwt.SimpleSigner(
              getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ), // Removing 0x from private key as input of SimpleSigner
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

      const { jwt, nonce } = await EbsiDidAuth.createDidAuthRequest(
        didAuthRequestCall
      );
      expect(nonce).toBeDefined();
      const { header, payload } = didJwt.decodeJWT(jwt);

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
      const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
      const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const didEntityAA = entityAA.did;
      const tokenEntityAA = entityAA.jwt;
      const didAuthRequestCall: DidAuthRequestCall = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        signatureUri: `${WALLET_API_BASE_URL}/wallet/v1/signatures`,
        authZToken: tokenEntityAA,
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DIDAUTH_KEY_ALGO.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const payload = {
          iss: entityAA.did,
          scope: DIAUTHScope.OPENID_DIDAUTHN,
          response_type: DIAUTHResponseType.ID_TOKEN,
          client_id: didAuthRequestCall.redirectUri,
          nonce: getNonce(),
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DIDAUTH_KEY_ALGO.ES256KR,
            signer: didJwt.SimpleSigner(
              getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ), // Removing 0x from private key as input of SimpleSigner
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

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

    it("should throw INVALID_AUDIENCE", async () => {
      expect.assertions(1);
      const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
      const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const payload = {
        aud: ["test", "test2"],
      };
      const jwt = JWT.sign(payload, entityAA.jwk, {
        header: {
          alg: "ES256K",
          typ: "JWT",
        },
      });
      await expect(
        EbsiDidAuth.verifyDidAuthRequest(jwt, RPC_ADDRESS, RPC_PROVIDER)
      ).rejects.toThrow(DIDAUTH_ERRORS.INVALID_AUDIENCE);
      jest.clearAllMocks();
    });
  });

  describe("eBSI DID Auth Response", () => {
    it("should throw BAD_PARAMS when no hexPrivateKey is present", async () => {
      expect.assertions(1);

      const didAuthResponseCall = {
        did: "",
        nonce: "",
        redirect_uri: "",
      };

      await expect(
        EbsiDidAuth.createDidAuthResponse(didAuthResponseCall as any)
      ).rejects.toThrow(DIDAUTH_ERRORS.BAD_PARAMS);
    });

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
      const { header, payload } = didJwt.decodeJWT(didAuthJwt);

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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DIDAUTH_KEY_TYPE.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };
      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
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
      jest.clearAllMocks();
    });

    it("should throw ERROR_VALIDATING_NONCE with a different nonce", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DIDAUTH_KEY_TYPE.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };
      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
      const didAuthJwt = await EbsiDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      await expect(
        EbsiDidAuth.verifyDidAuthResponse(
          didAuthJwt,
          `${WALLET_API_BASE_URL}/wallet/v1/signature-validations`,
          tokenEntityAA,
          "a bad nonce"
        )
      ).rejects.toThrow(DIDAUTH_ERRORS.ERROR_VALIDATING_NONCE);
      jest.clearAllMocks();
    });

    it("should throw ERROR_VERIFYING_SIGNATURE with a received status different from 204", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DIDAUTH_KEY_TYPE.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };
      jest.spyOn(axios, "post").mockResolvedValue({ status: 400 });
      const didAuthJwt = await EbsiDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      await expect(
        EbsiDidAuth.verifyDidAuthResponse(
          didAuthJwt,
          `${WALLET_API_BASE_URL}/wallet/v1/signature-validations`,
          tokenEntityAA,
          requestDIDAuthNonce
        )
      ).rejects.toThrow(DIDAUTH_ERRORS.ERROR_VERIFYING_SIGNATURE);
      jest.clearAllMocks();
    });

    it("should throw ERROR_VERIFYING_SIGNATURE with a error thrown from wallet verify signature", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const requestDIDAuthNonce: string = getNonce();
      const testKeyUser = generateTestKey(DIDAUTH_KEY_TYPE.EC);
      const didAuthResponseCall: DidAuthResponseCall = {
        hexPrivatekey: getHexPrivateKey(testKeyUser.key),
        did: testKeyUser.did,
        nonce: requestDIDAuthNonce,
        redirectUri: "http://localhost:8080/demo/spanish-university", // just assuming that we know that
      };
      jest
        .spyOn(axios, "post")
        .mockRejectedValue(new Error("Invalid Signature"));
      const didAuthJwt = await EbsiDidAuth.createDidAuthResponse(
        didAuthResponseCall
      );
      await expect(
        EbsiDidAuth.verifyDidAuthResponse(
          didAuthJwt,
          `${WALLET_API_BASE_URL}/wallet/v1/signature-validations`,
          tokenEntityAA,
          requestDIDAuthNonce
        )
      ).rejects.toThrow(DIDAUTH_ERRORS.ERROR_VERIFYING_SIGNATURE);
      jest.clearAllMocks();
    });
  });
});
