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
    const { jwt, idToken, did, hexPublicKey, header, payload } =
      await mockedIdToken({
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

  it("verifyDidAuthResponse for a did:key", async () => {
    expect.assertions(1);
    const WALLET_API_BASE_URL =
      process.env.WALLET_API_URL || "http://localhost:9000";
    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
      },
      nonce: "33kf-Y-IfB8EfiePqo0u7zZHO2O6Oswc_7h_dzE-Dsk",
      redirectUri: "https://dev.vidchain.net/siop/responses",
    };
    const idToken =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticWY4VURXb0Z4Z3VrUXBLRTJzVjNYYlJtTnpSUDFWUkRVd2Y3MnBZc3hieUdMc201V25KUFFueVNzalZmQ3JhNks2TExIa1ZMYnh4cThTZXZTRjdvZFRNbnRSVnVmTnExUWdyV1VUeVhhZzhLem5qempRQjJRczI3UkZxd2lYdTlGSiJ9.eyJpYXQiOjE2OTQwNzA4NzEsImlzcyI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUiLCJyZWRpcmVjdFVyaSI6Imh0dHBzOi8vZGV2LnZpZGNoYWluLm5ldC9zaW9wL3Jlc3BvbnNlcyIsImlkZW50aWZpZXJzVXJpIjoiaHR0cHM6Ly9kZXYudmlkY2hhaW4ubmV0L3dhbGxldC1hcGkvdjEvcmVzb2x2ZXIiLCJub25jZSI6IjMza2YtWS1JZkI4RWZpZVBxbzB1N3paSE8yTzZPc3djXzdoX2R6RS1Ec2siLCJzdGF0ZSI6IjZjZjMwMjczNTNjMDEwNjgyMzg1NTM0MiIsImF1ZCI6Imh0dHBzOi8vZGV2LnZpZGNoYWluLm5ldC9zaW9wL3Jlc3BvbnNlcyIsImRpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticWY4VURXb0Z4Z3VrUXBLRTJzVjNYYlJtTnpSUDFWUkRVd2Y3MnBZc3hieUdMc201V25KUFFueVNzalZmQ3JhNks2TExIa1ZMYnh4cThTZXZTRjdvZFRNbnRSVnVmTnExUWdyV1VUeVhhZzhLem5qempRQjJRczI3UkZxd2lYdTlGSiJ9.ICNqjeaf8GMrDH6A3_PjfWF6itbQscKQTHzyU3l0gCn86S1QgA9r55p6TW2teGbVlC20CK6lRzEE5VwuqNZbHQ";

    const didDocument = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
      ],
      id: "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
      verificationMethod: [
        {
          id: "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
          type: "JsonWebKey2020",
          controller:
            "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
          publicKeyJwk: {
            crv: "P-256",
            kty: "EC",
            x: "Z5-Rng1aqffn_N72B3vBGf5VPO8Jake0SACvEh8njL8",
            y: "9d4Rat2vguTyRyis5gOJtGX45hTM7BasEVGu-xXPJkQ",
          },
        },
      ],
      authentication: [
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
      ],
      assertionMethod: [
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
      ],
      capabilityInvocation: [
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
      ],
      capabilityDelegation: [
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbqf8UDWoFxgukQpKE2sV3XbRmNzRP1VRDUwf72pYsxbyGLsm5WnJPQnySsjVfCra6K6LLHkVLbxxq8SevSF7odTMntRVufNq1QgrWUTyXag8KznjzjQB2Qs27RFqwiXu9FJ",
      ],
    };
    jest.spyOn(axios, "get").mockResolvedValue({
      data: didDocument,
    });
    await expect(
      verifyDidAuthResponse(idToken, optsVerify)
    ).resolves.not.toThrow(DidAuthErrors.VERIFY_BAD_PARAMETERS);
    jest.clearAllMocks();
  });
});
