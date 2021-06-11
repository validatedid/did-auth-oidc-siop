import * as dotenv from "dotenv";
import axios from "axios";
import { verifyJWT, decodeJWT } from "did-jwt";
import { getParsedDidDocument, mockedIdToken } from "../AuxTest";
import { DidAuthErrors, DidAuthTypes, verifyDidAuthResponse } from "../../src";

// importing .env variables
dotenv.config();
jest.mock("axios");
jest.mock("did-jwt");
const mockDecodeJWT = decodeJWT as jest.Mock;
const mockVerifyJwt = verifyJWT as jest.Mock;
describe("SiopDidAuth tests should", () => {
  it("throw ERROR_VALIDATING_NONCE when nonce passed is not the same as in the id_token", async () => {
    expect.assertions(1);
    const WALLET_API_BASE_URL =
      process.env.WALLET_API_URL || "http://localhost:9000";
    const nonce = "zizu-nonce";
    const {
      jwt,
      idToken,
      did,
      hexPublicKey,
      header,
      payload,
    } = await mockedIdToken({
      nonce,
    });

    jest.spyOn(axios, "get").mockResolvedValue({
      data: getParsedDidDocument({
        did,
        publicKeyHex: hexPublicKey,
      }),
    });

    mockVerifyJwt.mockResolvedValue({ payload } as never);
    mockDecodeJWT.mockReturnValue({ header, payload } as never);
    jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken: jwt,
      },
      nonce: "some bad nonce",
      redirectUri: "https://app.example/demo",
    };

    await expect(verifyDidAuthResponse(idToken, optsVerify)).rejects.toThrow(
      DidAuthErrors.ERROR_VALIDATING_NONCE
    );
    jest.clearAllMocks();
  });

  it("throw VERIFY_BAD_PARAMETERS when no opts.nonce is passed", async () => {
    expect.assertions(1);
    const WALLET_API_BASE_URL =
      process.env.WALLET_API_URL || "http://localhost:9000";
    const nonce = "zizu-nonce";
    const { jwt, idToken } = await mockedIdToken({ nonce });

    const optsVerify = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken: jwt,
      },
    };

    await expect(verifyDidAuthResponse(idToken, optsVerify)).rejects.toThrow(
      DidAuthErrors.VERIFY_BAD_PARAMETERS
    );
    jest.clearAllMocks();
  });

  it("throw VERIFY_BAD_PARAMETERS when no opts is passed", async () => {
    expect.assertions(1);
    const nonce = "zizu-nonce";
    const { idToken } = await mockedIdToken({ nonce });

    await expect(verifyDidAuthResponse(idToken, {} as never)).rejects.toThrow(
      DidAuthErrors.VERIFY_BAD_PARAMETERS
    );
    jest.clearAllMocks();
  });

  it("throw VERIFY_BAD_PARAMETERS when no id_token is passed", async () => {
    expect.assertions(1);
    const WALLET_API_BASE_URL =
      process.env.WALLET_API_URL || "http://localhost:9000";
    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
      },
      nonce: "some nonce",
    };
    await expect(verifyDidAuthResponse("", optsVerify)).rejects.toThrow(
      DidAuthErrors.VERIFY_BAD_PARAMETERS
    );
    jest.clearAllMocks();
  });
});
