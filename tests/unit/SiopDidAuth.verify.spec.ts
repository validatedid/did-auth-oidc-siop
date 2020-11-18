import * as dotenv from "dotenv";
import axios from "axios";
import { verifyJWT, decodeJWT } from "did-jwt";
import { mockedIdToken } from "../AuxTest";
import { DidAuthErrors, DidAuthTypes, verifyDidAuthResponse } from "../../src";

// importing .env variables
dotenv.config();
jest.mock("axios");
jest.mock("did-jwt");
const mockDecodeJWT = decodeJWT as jest.Mock;
const mockVerifyJwt = verifyJWT as jest.Mock;
describe("SiopDidAuth tests should", () => {
  it("throw ERROR_VALIDATING_NONCE when nonce passed is not the same as in the payload", async () => {
    expect.assertions(1);
    const WALLET_API_BASE_URL =
      process.env.WALLET_API_URL || "http://localhost:9000";
    const nonce = "zizu-nonce";
    const { jwt, idToken } = mockedIdToken({ nonce });

    const payload = {
      nonce,
    };

    mockVerifyJwt.mockResolvedValue({ payload } as never);
    mockDecodeJWT.mockReturnValue({ payload } as never);
    jest.spyOn(axios, "post").mockResolvedValue({ status: 204 });
    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken: jwt,
      },
      nonce: "some bad nonce",
    };

    await expect(verifyDidAuthResponse(idToken, optsVerify)).rejects.toThrow(
      DidAuthErrors.ERROR_VALIDATING_NONCE
    );
    jest.clearAllMocks();
  });
});
