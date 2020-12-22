import axios from "axios";
import * as dotenv from "dotenv";
import parseJwk from "jose/jwk/parse";
import SignJWT from "jose/jwt/sign";
import { vidVerifyJwt, decodeJwt } from "@validatedid/did-jwt";
import {
  DidAuthErrors,
  DidAuthTypes,
  DidAuthUtil,
  verifyDidAuthRequest,
} from "../../src";
import { verifyDidAuth } from "../../src/AuxDidAuth";
import { getParsedDidDocument, mockedGetEnterpriseAuthToken } from "../AuxTest";

// importing .env variables
dotenv.config();
jest.mock("axios");
jest.mock("@validatedid/did-jwt");
const mockVerifyJwt = vidVerifyJwt as jest.Mock;
const mockDecodeJWT = decodeJwt as jest.Mock;

describe("vid DID Auth Request Validation", () => {
  it("should throw ERROR_VERIFYING_SIGNATURE", async () => {
    expect.assertions(1);
    const RPC_PROVIDER =
      "https://ropsten.infura.io/v3/f03e98e0dc2b855be647c39abe984fcf";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const entityAA = await mockedGetEnterpriseAuthToken("COMPANY AA INC");
    const header = {
      alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256K,
      typ: "JWT",
      kid: `${entityAA.did}#keys-1`,
    };
    const state = DidAuthUtil.getState();
    const payload: DidAuthTypes.DidAuthRequestPayload = {
      iss: entityAA.did,
      scope: DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN,
      response_type: DidAuthTypes.DidAuthResponseType.ID_TOKEN,
      client_id: "http://localhost:8080/demo/spanish-university",
      state,
      nonce: DidAuthUtil.getNonce(state),
      registration: {
        jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityAA.did};transform-keys=jwks`,
        id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256K,
      },
    };
    const privateKey = await parseJwk(
      entityAA.jwk,
      DidAuthTypes.DidAuthKeyAlgorithm.ES256K
    );
    const jwt = await new SignJWT(payload)
      .setProtectedHeader(header)
      .sign(privateKey);

    jest.spyOn(axios, "get").mockResolvedValue({
      data: getParsedDidDocument({
        did: entityAA.did,
        publicKeyHex: entityAA.hexPublicKey,
      }),
    });
    mockVerifyJwt.mockResolvedValue(undefined as never);
    mockDecodeJWT.mockReturnValue({ header, payload });

    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        registry: RPC_ADDRESS,
        rpcUrl: RPC_PROVIDER,
      },
    };
    await expect(verifyDidAuthRequest(jwt, optsVerify)).rejects.toThrow(
      DidAuthErrors.ERROR_VERIFYING_SIGNATURE
    );
    jest.clearAllMocks();
  });
});

describe("verifyDidAuth tests should", () => {
  it("throw VERIFY_BAD_PARAMETERS when no jwt is passed", async () => {
    expect.assertions(1);
    await expect(
      verifyDidAuth(undefined as never, undefined as never)
    ).rejects.toThrow(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  });

  it("throw VERIFY_BAD_PARAMETERS when no opts is passed", async () => {
    expect.assertions(1);
    await expect(
      verifyDidAuth("a valid jwt", undefined as never)
    ).rejects.toThrow(DidAuthErrors.VERIFY_BAD_PARAMETERS);
  });

  it("throw VERIFY_BAD_PARAMETERS when no opts.verificationType is passed", async () => {
    expect.assertions(1);
    await expect(verifyDidAuth("a valid jwt", {} as never)).rejects.toThrow(
      DidAuthErrors.VERIFY_BAD_PARAMETERS
    );
  });
});
