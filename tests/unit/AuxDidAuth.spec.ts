import * as dotenv from "dotenv";
import axios from "axios";
import * as didJwt from "@validatedid/did-jwt";
import { parse } from "querystring";
import { keyUtils } from "@transmute/did-key-ed25519";
import {
  getParsedDidDocument,
  mockedGetEnterpriseAuthToken,
  mockedKeyAndDid,
  mockedKeyAndDidKey,
} from "../AuxTest";
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
  DidAuthJwk,
} from "../../src";
import * as mockedData from "../data/mockedData";
import {
  createDidAuthRequestPayload,
  createDidAuthResponsePayload,
  signDidAuthInternal,
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
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
          kid: `${didAA}#keys-1`,
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
          kid: `${entityAA.did}#keys-1`,
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
        const jws = await didJwt.createJwt(
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
      jest.clearAllMocks();
    });

    it("should throw MALFORMED_SIGNATURE_RESPONSE", async () => {
      expect.assertions(1);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
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
          kid: `${didAA}#keys-1`,
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
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
          kid: `${didAA}#keys-1`,
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
          kid: `${entityAA.did}#keys-1`,
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
        const jws = await didJwt.createJwt(
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
      const { header, payload } = didJwt.decodeJwt(jwt);

      const expectedHeader = { ...mockedData.DIDAUTH_HEADER };
      expectedHeader.alg = "ES256K-R";
      expectedHeader.kid = `${entityAA.did}#keys-1`;
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
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
          kid: `${didAA}#keys-1`,
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
          kid: `${entityAA.did}#keys-1`,
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
        const jws = await didJwt.createJwt(
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
      const { header, payload } = didJwt.decodeJwt(jwt);

      const expectedHeader = { ...mockedData.DIDAUTH_HEADER };
      expectedHeader.alg = "ES256K-R";
      expectedHeader.kid = `${entityAA.did}#keys-1`;
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
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
          kid: `${didAA}#keys-1`,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
          referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${didAA};transform-keys=jwks`,
        },
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: getParsedDidDocument({
          did: entityAA.did,
          publicKeyHex: entityAA.hexPublicKey,
        }),
      });
      jest.spyOn(axios, "post").mockImplementation(async () => {
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${entityAA.did}#keys-1`,
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
        const jws = await didJwt.createJwt(
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

    it("should return a valid payload on DID Auth request validation when using did:key", async () => {
      expect.assertions(7);
      const { hexPrivateKey, did, hexPublicKey } = await mockedKeyAndDidKey();
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
      jest.spyOn(axios, "get").mockResolvedValue({
        data: {
          "@context": ["https://www.w3.org/ns/did/v1", { "@base": did }],
          id: did,
          verificationMethod: [
            {
              id: `#${did.substring(8)}`,
              type: "Ed25519VerificationKey2018",
              controller: did,
              publicKeyBase58: keyUtils.publicKeyBase58FromPublicKeyHex(
                hexPublicKey
              ) as string,
            },
            {
              id: "#z6LSjg5maTATQUt5JE6bbdZ13RbwccUf868p1PXRfvkqtJoa",
              type: "X25519KeyAgreementKey2019",
              controller: did,
              publicKeyBase58: "8zuc49MbK2ALCqiq4z33iqPTmTwYRUxf8QokBU7KAw2p",
            },
          ],
          authentication: [`#${did.substring(8)}`],
          assertionMethod: [`#${did.substring(8)}`],
          capabilityInvocation: [`#${did.substring(8)}`],
          capabilityDelegation: [`#${did.substring(8)}`],
          keyAgreement: ["#z6LSjg5maTATQUt5JE6bbdZ13RbwccUf868p1PXRfvkqtJoa"],
        },
      });
      const { jwt } = await createDidAuthRequest(opts);
      expect(jwt).toBeDefined(); // OK
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          registry: process.env.DID_REGISTRY_SC_ADDRESS,
          rpcUrl: process.env.DID_PROVIDER_RPC_URL,
          didUrlResolver: "https://dev.vidchain.net/api/v1/identifiers",
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
      jest.clearAllMocks();
    });

    it("should throw REGISTRATION_OBJECT_TYPE_NOT_SET when no registrationType is present", async () => {
      expect.assertions(1);

      const opts = {};

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
      );
    });
    it("should throw REGISTRATION_OBJECT_TYPE_NOT_SET when no registrationType.type is present", async () => {
      expect.assertions(1);

      const opts = {
        registrationType: {},
      };

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
      );
    });

    it("should throw ObjectPassedBy is REFERENCE and no referenceUri is set", async () => {
      expect.assertions(1);

      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        },
      };

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.NO_REFERENCE_URI
      );
    });

    it("should create a valid payload when registration type is VALUE and is an external signature", async () => {
      expect.assertions(3);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/identifiers/${did}`,
          did,
        },
      };

      jest.spyOn(axios, "get").mockResolvedValue({
        data: {
          verificationMethod: [
            {
              publicKeyJwk: {
                kty: "EC",
                crv: "secp256k1",
                x:
                  "62451c7a3e0c6e2276960834b79ae491ba0a366cd6a1dd814571212ffaeaaf5a",
                y:
                  "1ede3d754090437db67eca78c1659498c9cf275d2becc19cdc8f1ef76b9d8159",
                kid: "JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
              },
            },
          ],
        },
      } as never);

      const response = await createDidAuthRequestPayload(opts as never);
      expect(response).toBeDefined();
      expect(response.registration).toBeDefined();
      expect(response.registration).toHaveProperty("jwks");
    });

    it("should throw ERROR_RETRIEVING_DID_DOCUMENT when DID Document could not be retrieved", async () => {
      expect.assertions(1);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/identifiers/${did}`,
          did,
        },
      };
      jest.spyOn(axios, "get").mockResolvedValue(undefined as never);

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT
      );
    });

    it("should throw ERROR_RETRIEVING_DID_DOCUMENT when DID Document data is not set", async () => {
      expect.assertions(1);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/identifiers/${did}`,
          did,
        },
      };
      jest.spyOn(axios, "get").mockResolvedValue({} as never);

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT
      );
    });

    it("should throw ERROR_RETRIEVING_DID_DOCUMENT when DID Document verificationMethod is not set", async () => {
      expect.assertions(1);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/identifiers/${did}`,
          did,
        },
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: {},
      } as never);

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT
      );
    });

    it("should throw ERROR_RETRIEVING_DID_DOCUMENT when DID Document verificationMethod is an empty array", async () => {
      expect.assertions(1);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/identifiers/${did}`,
          did,
        },
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: {
          verificationMethod: [],
        },
      } as never);

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT
      );
    });

    it("should throw ERROR_RETRIEVING_DID_DOCUMENT when DID Document verificationMethod[0].publicKeyJwk is not set", async () => {
      expect.assertions(1);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          signatureUri: `http://localhost:8080/api/v1/identifiers/${did}`,
          did,
        },
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: {
          verificationMethod: [{}],
        },
      } as never);

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.ERROR_RETRIEVING_DID_DOCUMENT
      );
    });

    it("should throw SIGNATURE_OBJECT_TYPE_NOT_SET when reference URI is not set and it is not an internal signature", async () => {
      expect.assertions(1);
      const did = "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0";
      const opts = {
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          did,
        },
      };

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.SIGNATURE_OBJECT_TYPE_NOT_SET
      );
    });

    it("should throw REGISTRATION_OBJECT_TYPE_NOT_SET when objectpassedby is neither REFERENCE nor VALUE", async () => {
      expect.assertions(1);

      const opts = {
        registrationType: {
          type: "other type",
        },
      };

      await expect(createDidAuthRequestPayload(opts as never)).rejects.toThrow(
        DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
      );
    });

    it("create a registration by value when no kid is passed", async () => {
      expect.assertions(1);
      const { hexPrivateKey, did } = await mockedKeyAndDid();

      const opts: DidAuthTypes.DidAuthRequestOpts = {
        redirectUri: "http://localhost:8080/demo/spanish-university",
        requestObjectBy: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        signatureType: {
          hexPrivateKey,
          did,
        },
      };

      const requestPayload = await createDidAuthRequestPayload(opts);
      expect(requestPayload).toBeDefined();
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
      const { hexPrivateKey, did } = await mockedKeyAndDid();
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

      const didAuthJwt = await createDidAuthResponse(opts);
      const { header, payload } = didJwt.decodeJwt(didAuthJwt);

      const expectedHeader = { ...mockedData.DIDAUTH_HEADER };
      expectedHeader.kid = `${did}#keys-1`;
      expectedHeader.alg = "ES256K";
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
      const { hexPrivateKey, did } = await mockedKeyAndDid();
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
        vp: mockedData.verifiableIdPresentation,
      };

      const didAuthJwt = await createDidAuthResponse(opts);
      const { header, payload } = didJwt.decodeJwt(didAuthJwt);

      const expectedHeader = { ...mockedData.DIDAUTH_HEADER };
      expectedHeader.kid = `${did}#keys-1`;
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

    it("should create a JWT DID Auth Response token with Verifiable Presentation when using did:key", async () => {
      expect.assertions(2);
      const { hexPrivateKey, did } = await mockedKeyAndDidKey();
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
        vp: mockedData.verifiableIdPresentation,
      };

      const didAuthJwt = await createDidAuthResponse(opts);
      const { header, payload } = didJwt.decodeJwt(didAuthJwt);

      const expectedHeader = { ...mockedData.DIDAUTH_HEADER };
      expectedHeader.kid = `#${did.substring(8)}`;
      expectedHeader.alg = "EdDSA";
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
        `#${did.substring(8)}`
      ) as string;
      expectedPayload.sub_jwk.x = expect.any(String) as string;
      expectedPayload.sub_jwk.y = expect.any(String) as string;
      expectedPayload.sub_jwk.crv = "ed25519";
      expectedPayload.sub = expect.any(String) as string;

      expect(header).toMatchObject(expectedHeader);
      expect(payload).toMatchObject(expectedPayload);
      jest.clearAllMocks();
    });

    it("should return valid payload on DID Auth Response validation", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "http://localhost:9000";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const { hexPrivateKey, did, hexPublicKey } = await mockedKeyAndDid();
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
      jest.spyOn(axios, "get").mockResolvedValue({
        data: getParsedDidDocument({
          did,
          publicKeyHex: hexPublicKey,
        }),
      });

      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce,
        redirectUri: opts.redirectUri,
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

    it("should return valid payload on DID Auth Response validation when using did:key", async () => {
      expect.assertions(3);
      const WALLET_API_BASE_URL =
        process.env.WALLET_API_URL || "https://dev.vidchain.net";
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const { hexPrivateKey, did, hexPublicKey } = await mockedKeyAndDidKey();
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
      jest.spyOn(axios, "get").mockResolvedValue({
        data: {
          "@context": ["https://www.w3.org/ns/did/v1", { "@base": did }],
          id: did,
          verificationMethod: [
            {
              id: `#${did.substring(8)}`,
              type: "Ed25519VerificationKey2018",
              controller: did,
              publicKeyBase58: keyUtils.publicKeyBase58FromPublicKeyHex(
                hexPublicKey
              ) as string,
            },
            {
              id: "#z6LSjg5maTATQUt5JE6bbdZ13RbwccUf868p1PXRfvkqtJoa",
              type: "X25519KeyAgreementKey2019",
              controller: did,
              publicKeyBase58: "8zuc49MbK2ALCqiq4z33iqPTmTwYRUxf8QokBU7KAw2p",
            },
          ],
          authentication: [`#${did.substring(8)}`],
          assertionMethod: [`#${did.substring(8)}`],
          capabilityInvocation: [`#${did.substring(8)}`],
          capabilityDelegation: [`#${did.substring(8)}`],
          keyAgreement: ["#z6LSjg5maTATQUt5JE6bbdZ13RbwccUf868p1PXRfvkqtJoa"],
        },
      });

      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce,
        redirectUri: opts.redirectUri,
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const state = DidAuthUtil.getState();
      const requestDIDAuthNonce = DidAuthUtil.getNonce(state);
      const { hexPrivateKey, did, hexPublicKey } = await mockedKeyAndDid();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce: requestDIDAuthNonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: getParsedDidDocument({
          did,
          publicKeyHex: hexPublicKey,
        }),
      });
      jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce: "a bad nonce",
        redirectUri: opts.redirectUri,
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const requestDIDAuthNonce = DidAuthUtil.getNonce(state);
      const { hexPrivateKey, did, hexPublicKey } = await mockedKeyAndDid();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce: requestDIDAuthNonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: getParsedDidDocument({
          did,
          publicKeyHex: hexPublicKey,
        }),
      });
      jest.spyOn(axios, "post").mockResolvedValue({ status: 400 });
      const didAuthJwt = await createDidAuthResponse(opts);
      const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
        verificationType: {
          verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
          authZToken: tokenEntityAA,
        },
        nonce,
        redirectUri: opts.redirectUri,
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
      const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
      const tokenEntityAA = entityAA.jwt;
      const state = DidAuthUtil.getState();
      const nonce = DidAuthUtil.getNonce(state);
      const requestDIDAuthNonce = DidAuthUtil.getNonce(state);
      const { hexPrivateKey, did, hexPublicKey } = await mockedKeyAndDid();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://app.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
          kid: `${did}#keys-1`,
        },
        nonce: requestDIDAuthNonce,
        state,
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      jest.spyOn(axios, "get").mockResolvedValue({
        data: getParsedDidDocument({
          did,
          publicKeyHex: hexPublicKey,
        }),
      });
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
        redirectUri: opts.redirectUri,
      };
      await expect(
        verifyDidAuthResponse(didAuthJwt, optsVerify)
      ).rejects.toThrow(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
      jest.clearAllMocks();
    });
    it("should throw BAD_PARAMS when no opts is set", async () => {
      expect.assertions(1);

      await expect(
        createDidAuthResponsePayload(undefined as never)
      ).rejects.toThrow(DidAuthErrors.BAD_PARAMS);
    });

    it("should throw BAD_PARAMS when no opts.redirectUri is set", async () => {
      expect.assertions(1);

      const opts = {};

      await expect(createDidAuthResponsePayload(opts as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
    });

    it("should throw BAD_PARAMS when no opts.signatureType is set", async () => {
      expect.assertions(1);

      const opts = {
        redirectUri: "http://localhost.example/demo",
      };

      await expect(createDidAuthResponsePayload(opts as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
    });

    it("should throw BAD_PARAMS when no opts.nonce is set", async () => {
      expect.assertions(1);

      const opts = {
        redirectUri: "http://localhost.example/demo",
        signatureType: {},
      };

      await expect(createDidAuthResponsePayload(opts as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
    });

    it("should throw BAD_PARAMS when no opts.did is set", async () => {
      expect.assertions(1);

      const opts = {
        redirectUri: "http://localhost.example/demo",
        signatureType: {},
        nonce: "zizu-nonce",
      };

      await expect(createDidAuthResponsePayload(opts as never)).rejects.toThrow(
        DidAuthErrors.BAD_PARAMS
      );
    });
  });

  describe("signDidAuthInternal tests should", () => {
    it("sign when no kid is passed", async () => {
      expect.assertions(1);
      const { hexPrivateKey, did } = await mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const requestPayload: DidAuthTypes.DidAuthRequestPayload = {
        iss: did,
        scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
        registration: {
          jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${did};transform-keys=jwks`,
          id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256K,
        },
        client_id: "http://app.example/demo",
        state,
        nonce: DidAuthUtil.getNonce(state),
        response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
      };
      const response = await signDidAuthInternal(
        requestPayload,
        did,
        hexPrivateKey
      );
      expect(response).toBeDefined();
    });
    it("sign when using did:key", async () => {
      expect.assertions(1);
      const { hexPrivateKey, did } = await mockedKeyAndDidKey();
      const state = DidAuthUtil.getState();
      const requestPayload: DidAuthTypes.DidAuthRequestPayload = {
        iss: did,
        scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
        registration: {
          jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${did};transform-keys=jwks`,
          id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.EDDSA,
        },
        client_id: "http://app.example/demo",
        state,
        nonce: DidAuthUtil.getNonce(state),
        response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
      };
      const response = await signDidAuthInternal(
        requestPayload,
        did,
        hexPrivateKey
      );
      expect(response).toBeDefined();
    });
  });

  describe("createDidAuthResponsePayload tests should", () => {
    it("create a response payload with no kid provided", async () => {
      expect.assertions(1);
      const { hexPrivateKey, did } = await mockedKeyAndDid();
      const state = DidAuthUtil.getState();
      const opts: DidAuthTypes.DidAuthResponseOpts = {
        redirectUri: "https://entity.example/demo",
        signatureType: {
          hexPrivateKey,
          did,
        },
        state,
        nonce: DidAuthUtil.getNonce(state),
        registrationType: {
          type: DidAuthTypes.ObjectPassedBy.VALUE,
        },
        did,
      };
      const responsePayload = createDidAuthResponsePayload(opts);
      expect(responsePayload).toBeDefined();
    });
  });
});
