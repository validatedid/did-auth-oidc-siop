import { JWT, JWK } from "jose";
import { verifyJWT, decodeJWT } from "did-jwt";
import { EbsiDidAuth, DIDAUTH_ERRORS } from "../src";

jest.mock("did-jwt");
const mockVerifyJwt = verifyJWT as jest.Mock;
const mockDecodeJWT = decodeJWT as jest.Mock;

describe("eBSI DID Auth Request Validation", () => {
  it("should throw ERROR_VERIFYING_SIGNATURE", async () => {
    expect.assertions(1);
    const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
    const payload = {};
    const jwt = JWT.sign(payload, jwk, {
      header: {
        alg: "ES256K",
        typ: "JWT",
      },
    });
    mockVerifyJwt.mockResolvedValue(undefined as any);
    mockDecodeJWT.mockReturnValue({ payload: { aud: "" } });
    await expect(
      EbsiDidAuth.verifyDidAuthRequest(jwt, RPC_ADDRESS, RPC_PROVIDER)
    ).rejects.toThrow(DIDAUTH_ERRORS.ERROR_VERIFYING_SIGNATURE);
    jest.clearAllMocks();
  });
  it("should throw NO_AUDIENCE", async () => {
    expect.assertions(1);
    const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
    const payload = {};
    const jwt = JWT.sign(payload, jwk, {
      header: {
        alg: "ES256K",
        typ: "JWT",
      },
    });
    mockVerifyJwt.mockResolvedValue(undefined as any);
    mockDecodeJWT.mockReturnValue({} as any);
    await expect(
      EbsiDidAuth.verifyDidAuthRequest(jwt, RPC_ADDRESS, RPC_PROVIDER)
    ).rejects.toThrow(DIDAUTH_ERRORS.NO_AUDIENCE);
    jest.clearAllMocks();
  });

  it("should return a string audience", async () => {
    expect.assertions(2);
    const RPC_PROVIDER = "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
    const payload = {
      aud: "did:ebsi:0x0abcd",
    };
    const jwt = JWT.sign(payload, jwk, {
      header: {
        alg: "ES256K",
        typ: "JWT",
      },
    });
    mockVerifyJwt.mockResolvedValue({ payload } as any);
    mockDecodeJWT.mockReturnValue({ payload } as any);
    const response = await EbsiDidAuth.verifyDidAuthRequest(
      jwt,
      RPC_ADDRESS,
      RPC_PROVIDER
    );
    expect(response).toBeDefined();
    expect(response).toMatchObject(payload);
    jest.clearAllMocks();
  });
});
