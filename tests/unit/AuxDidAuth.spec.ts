import * as dotenv from "dotenv";
import axios from "axios";
import * as didJwt from "did-jwt";
import { JWT } from "jose";
import { parse } from "querystring";
import { mockedGetEnterpriseAuthToken, mockedKeyAndDid } from "../AuxTest";
import {
  createUriRequest,
  createDidAuthRequest,
  createDidAuthResponse,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
  JWTHeader,
  DidAuthErrors,
  DidAuthTypes,
  DidAuthUtil,
} from "../../src";
import * as mockedData from "../data/mockedData";
import {
  createDidAuthRequestPayload,
  createDidAuthResponsePayload,
} from "../../src/AuxDidAuth";

// importing .env variables
dotenv.config();
jest.mock("axios");

describe("vidDidAuth", () => {
  describe("vid DID Auth Request", () => {
    it("should throw BAD_PARAMS when no client_id is present", async () => {
      expect.assertions(1);

      const didAuthRequestCall = {
        signatureUri: "",
        authZToken: "",
      };

      await expect(
        createUriRequest(didAuthRequestCall as never)
      ).rejects.toThrow(DidAuthErrors.BAD_PARAMS);
    });

    it("should throw BAD_PARAMS when no params is passed", async () => {
      expect.assertions(1);

      await expect(createUriRequest(undefined as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
    });

    it("should create a DID Auth Request URL with a JWT as reference", async () => {
      expect.assertions(12);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAA = entityAA.did;

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
          did: didAA,
          authZToken: tokenEntityAA,
          kid: `${didAA}#key-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${didAA};transform-keys=jwks`,
        },
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const state = DidAuthUtil.getState();
        const payload: DidAuthTypes.DidAuthRequestPayload = {
          iss: entityAA.did,
          scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
          response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
          client_id: opts.redirectUri,
          state,
          nonce: DidAuthUtil.getNonce(state),
          registration: {
            jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
            id_token_signed_response_alg:
              DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          },
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
            signer: didJwt.SimpleSigner(
              DidAuthUtil.getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ),
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

      const uriRequest = await createUriRequest(opts);
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
      jest.clearAllMocks();
    });

    it("should throw MALFORMED_SIGNATURE_RESPONSE", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAA = entityAA.did;
      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
          did: didAA,
          authZToken: tokenEntityAA,
          kid: `${didAA}#key-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${didAA};transform-keys=jwks`,
        },
      };
      jest.spyOn(axios, "post").mockResolvedValue({
        status: 400,
        data: { jws: undefined },
      });

      await expect(createDidAuthRequest(opts)).rejects.toThrow(
        DidAuthErrors.MALFORMED_SIGNATURE_RESPONSE
      );
      jest.clearAllMocks();
    });

    it("should throw BAD_PARAMS", async () => {
      expect.assertions(1);
      const opts = {
        signatureUri: "",
      };
      await expect(createDidAuthRequest(opts as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
      jest.clearAllMocks();
    });

    it('should create a JWT DID Auth Request token with "ES256K-R" algo using wallet keys from a random Enterprise', async () => {
      expect.assertions(7);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAA = entityAA.did;

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
          did: didAA,
          authZToken: tokenEntityAA,
          kid: `${didAA}#key-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${didAA};transform-keys=jwks`,
        },
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const state = DidAuthUtil.getState();
        const payload: DidAuthTypes.DidAuthRequestPayload = {
          iss: entityAA.did,
          scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
          response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
          client_id: opts.redirectUri,
          state,
          nonce: DidAuthUtil.getNonce(state),
          registration: {
            jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
            id_token_signed_response_alg:
              DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          },
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
            signer: didJwt.SimpleSigner(
              DidAuthUtil.getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ),
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

      const { jwt, nonce, state } = await createDidAuthRequest(opts);

      expect(jwt).toBeDefined();
      expect(nonce).toBeDefined();
      expect(state).toBeDefined();
      const { header, payload } = didJwt.decodeJWT(jwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${entityAA.did}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = entityAA.did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.state = expect.any(String) as string;
      expectedPayload.client_id = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.registration = {
        jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
        id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
      };
      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60);
      jest.clearAllMocks();
    });

    it("should create a DID Auth Request with vc claims", async () => {
      expect.assertions(7);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAA = entityAA.did;

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
          did: didAA,
          authZToken: tokenEntityAA,
          kid: `${didAA}#key-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${didAA};transform-keys=jwks`,
        },
        claims: mockedData.verifiableIdOidcClaim,
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const state = DidAuthUtil.getState();
        const payload: DidAuthTypes.DidAuthRequestPayload = {
          iss: entityAA.did,
          scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
          response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
          client_id: opts.redirectUri,
          state,
          nonce: DidAuthUtil.getNonce(state),
          registration: {
            jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
            id_token_signed_response_alg:
              DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          },
          claims: mockedData.verifiableIdOidcClaim,
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
            signer: didJwt.SimpleSigner(
              DidAuthUtil.getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ),
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

      const { jwt, nonce, state } = await createDidAuthRequest(opts);

      expect(jwt).toBeDefined();
      expect(nonce).toBeDefined();
      expect(state).toBeDefined();
      const { header, payload } = didJwt.decodeJWT(jwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${entityAA.did}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD_CLAIMS;
      expectedPayload.iss = entityAA.did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.state = expect.any(String) as string;
      expectedPayload.client_id = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.registration = {
        jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
        id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
      };
      expect(payload.iat).toBeDefined();
      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      expect(payload.exp).toStrictEqual(payload.iat + 5 * 60);
      jest.clearAllMocks();
    });

    it("should return a valid payload on DID Auth request validation", async () => {
      expect.assertions(7);
      const RPC_PROVIDER =
        process.env.DID_PROVIDER_RPC_URL ||
        "https://ropsten.infura.io/v3/f03e98e0dc2b855be647c39abe984fcf";
      const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const didAA = entityAA.did;

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: "https://dev.vidchain.net/siop/jwts",
        },
        signatureType: {
          signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
          did: didAA,
          authZToken: tokenEntityAA,
          kid: `${didAA}#key-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${didAA};transform-keys=jwks`,
        },
      };
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#key-1`,
        };
        const state = DidAuthUtil.getState();
        const payload: DidAuthTypes.DidAuthRequestPayload = {
          iss: entityAA.did,
          scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
          response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
          client_id: opts.redirectUri,
          state,
          nonce: DidAuthUtil.getNonce(state),
          registration: {
            jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
            id_token_signed_response_alg:
              DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          },
        };
        const jws = await didJwt.createJWT(
          payload,
          {
            issuer: entityAA.did,
            alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
            signer: didJwt.SimpleSigner(
              DidAuthUtil.getHexPrivateKey(entityAA.jwk).replace("0x", "")
            ),
            expiresIn: 5 * 60,
          },
          header
        );
        return {
          status: 200,
          data: { jws },
        };
      });

      const { jwt } = await createDidAuthRequest(opts);
      expect(jwt).toBeDefined();
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          registry: RPC_ADDRESS,
          rpcUrl: RPC_PROVIDER,
        },
      };
      const validationResponse = await verifyDidAuthRequest(jwt, optsVerify);
      expect(validationResponse).toBeDefined();
      expect(validationResponse.signatureValidation).toBe(true);
      expect(validationResponse.payload).toBeDefined();

      const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
      expectedPayload.iss = entityAA.did;
      expectedPayload.nonce = expect.any(String) as string;
      expectedPayload.state = expect.any(String) as string;
      expectedPayload.client_id = opts.redirectUri;
      expectedPayload.iat = expect.any(Number) as number;
      expectedPayload.exp = expect.any(Number) as number;
      expectedPayload.registration = {
        jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
        id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
      };

      expect(validationResponse.payload.iat).toBeDefined();
      expect(validationResponse.payload).toMatchObject(expectedPayload);
      expect(validationResponse.payload.exp).toStrictEqual(
        validationResponse.payload.iat + 5 * 60
      ); // 5 minutes of expiration time
      jest.clearAllMocks();
    });

    it("should throw INVALID_AUDIENCE", async () => {
      expect.assertions(1);
      const RPC_PROVIDER =
        process.env.DID_PROVIDER_RPC_URL ||
        "https://ropsten.infura.io/v3/f03e98e0dc2b855be647c39abe984fcf";
      const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const payload = {
        aud: ["test", "test2"],
      };
      const jwt = JWT.sign(payload, entityAA.jwk, {
        header: {
          alg: "ES256K",
          typ: "JWT",
        },
      });
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          registry: RPC_ADDRESS,
          rpcUrl: RPC_PROVIDER,
        },
      };

      await expect(verifyDidAuthRequest(jwt, optsVerify)).rejects.toThrow(
        DidAuthErrors.INVALID_AUDIENCE
      );
      jest.clearAllMocks();
    });

    it("should throw REGISTRATION_OBJECT_TYPE_NOT_SET when no registrationType is present", () => {
      expect.assertions(1);

      const opts = {};

      expect(() => createDidAuthRequestPayload(opts as never)).toThrow(
        DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
      );
    });
    it("should throw REGISTRATION_OBJECT_TYPE_NOT_SET when no registrationType.type is present", () => {
      expect.assertions(1);

      const opts = {
        registrationType: {},
      };

      expect(() => createDidAuthRequestPayload(opts as never)).toThrow(
        DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
      );
    });

    it("should throw ObjectPassedBy is REFERENCE and no referenceUri is set", () => {
      expect.assertions(1);

      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        },
      };

      expect(() => createDidAuthRequestPayload(opts as never)).toThrow(
        DidAuthErrors.NO_REFERENCE_URI
      );
    });

    it("should throw registration type is VALUE and is an external signature", () => {
      expect.assertions(1);

      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/signatures`,
          did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        },
      };

      expect(() => createDidAuthRequestPayload(opts as never)).toThrow(
        "Option not implemented"
      );
    });

    it("should throw REGISTRATION_OBJECT_TYPE_NOT_SET when objectpassedby is neither REFERENCE nor VALUE", () => {
      expect.assertions(1);

      const opts = {
        registrationType: {
          type: "other type",
        },
      };

      expect(() => createDidAuthRequestPayload(opts as never)).toThrow(
        DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
      );
    });
  });

  describe("vid DID Auth Response", () => {
    it("should throw BAD_PARAMS when no all required parameters are present", async () => {
      expect.assertions(1);

      const opts = {
        did: "",
        nonce: "",
        redirect_uri: "",
      };

      await expect(createDidAuthResponse(opts as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
    });

    it('should create a JWT DID Auth Response token with "ES256K-R" algo and random keys generated', async () => {
      expect.assertions(4);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-1`,
        },
        nonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      const didAuthJwt = await createDidAuthResponse(opts);
      const { header, payload } = didJwt.decodeJWT(didAuthJwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${did}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD;
      expectedPayload.iss = expect.stringMatching(
        DidAuthTypes.DidAuthResponseIss.SELF_ISSUE
      ) as DidAuthTypes.DidAuthResponseIss.SELF_ISSUE;
      expectedPayload.aud = opts.redirectUri;
      expectedPayload.did = did;
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
      jest.clearAllMocks();
    });

    it("should create a JWT DID Auth Response token with Verifiable Presentation", async () => {
      expect.assertions(2);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-1`,
        },
        nonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
        vp: mockedData.verifiableIdPresentation,
      };

      const didAuthJwt = await createDidAuthResponse(opts);
      const { header, payload } = didJwt.decodeJWT(didAuthJwt);

      const expectedHeader = mockedData.DIDAUTH_HEADER;
      expectedHeader.kid = `${did}#key-1`;
      const expectedPayload = mockedData.DIDAUTH_RESPONSE_PAYLOAD_VP;
      expectedPayload.iss = expect.stringMatching(
        DidAuthTypes.DidAuthResponseIss.SELF_ISSUE
      ) as DidAuthTypes.DidAuthResponseIss.SELF_ISSUE;
      expectedPayload.aud = opts.redirectUri;
      expectedPayload.did = did;
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
      jest.clearAllMocks();
    });

    it("should return valid payload on DID Auth Response validation", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-1`,
        },
        nonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };

      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce,
      };
      const validationResponse = await verifyDidAuthResponse(
        didAuthJwt,
        optsVerify
      );
      expect(validationResponse).toBeDefined();
      expect(validationResponse).toHaveProperty("signatureValidation");
      expect(validationResponse.signatureValidation).toBe(true);
      jest.clearAllMocks();
    });

    it("should throw ERROR_VALIDATING_NONCE with a different nonce", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const state = DidAuthUtil.getState();
      const requestDIDAuthNonce = DidAuthUtil.getNonce(state);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-1`,
        },
        nonce: requestDIDAuthNonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce: "a bad nonce",
      };
      await expect(
        verifyDidAuthResponse(didAuthJwt, optsVerify)
      ).rejects.toThrow(DidAuthErrors.ERROR_VALIDATING_NONCE);
      jest.clearAllMocks();
    });

    it("should throw ERROR_VERIFYING_SIGNATURE with a received status different from 204", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const requestDIDAuthNonce = DidAuthUtil.getNonce(state);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-1`,
        },
        nonce: requestDIDAuthNonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      jest.spyOn(axios, "post").mockResolvedValue({ status: 400 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce,
      };
      await expect(
        verifyDidAuthResponse(didAuthJwt, optsVerify)
      ).rejects.toThrow(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
      jest.clearAllMocks();
    });

    it("should throw ERROR_VERIFYING_SIGNATURE with a error thrown from wallet verify signature", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const requestDIDAuthNonce = DidAuthUtil.getNonce(state);
      const { hexPrivateKey, did } = mockedKeyAndDid();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#key-1`,
        },
        nonce: requestDIDAuthNonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      jest
        .spyOn(axios, "post")
        .mockRejectedValue(new Error("Invalid Signature"));
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce,
      };
      await expect(
        verifyDidAuthResponse(didAuthJwt, optsVerify)
      ).rejects.toThrow(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
      jest.clearAllMocks();
    });
  });

  it("should throw BAD_PARAMS when no opts is set", () => {
    expect.assertions(1);

    expect(() => createDidAuthResponsePayload(undefined as never)).toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("should throw BAD_PARAMS when no opts.redirectUri is set", () => {
    expect.assertions(1);

    const opts = {};

    expect(() => createDidAuthResponsePayload(opts as never)).toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("should throw BAD_PARAMS when no opts.signatureType is set", () => {
    expect.assertions(1);

    const opts = {
      redirectUri: "http://localhost.example/demo",
    };

    expect(() => createDidAuthResponsePayload(opts as never)).toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("should throw BAD_PARAMS when no opts.nonce is set", () => {
    expect.assertions(1);

    const opts = {
      redirectUri: "http://localhost.example/demo",
      signatureType: {},
    };

    expect(() => createDidAuthResponsePayload(opts as never)).toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("should throw BAD_PARAMS when no opts.did is set", () => {
    expect.assertions(1);

    const opts = {
      redirectUri: "http://localhost.example/demo",
      signatureType: {},
      nonce: "zizu-nonce",
    };

    expect(() => createDidAuthResponsePayload(opts as never)).toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });
});
