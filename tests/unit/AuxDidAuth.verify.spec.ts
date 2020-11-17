import { JWT, JWK } from "jose";
import { verifyJWT, decodeJWT } from "did-jwt";
import { DidAuthErrors, DidAuthTypes, verifyDidAuthRequest } from "../../src";

jest.mock("did-jwt");
const mockVerifyJwt = verifyJWT as jest.Mock;
const mockDecodeJWT = decodeJWT as jest.Mock;

describe("vid DID Auth Request Validation", () => {
  it("should throw ERROR_VERIFYING_SIGNATURE", async () => {
    expect.assertions(1);
    const RPC_PROVIDER =
      "https://ropsten.infura.io/v3/f03e98e0dc2b855be647c39abe984fcf";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
    const payload = {};
    const jwt = JWT.sign(payload, jwk, {
      header: {
        alg: "ES256K",
        typ: "JWT",
      },
    });
    mockVerifyJwt.mockResolvedValue(undefined as never);
    mockDecodeJWT.mockReturnValue({ payload: { aud: "" } });
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
  it("should throw NO_AUDIENCE", async () => {
    expect.assertions(1);
    const RPC_PROVIDER =
      "https://ropsten.infura.io/v3/f03e98e0dc2b855be647c39abe984fcf";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
    const payload = {};
    const jwt = JWT.sign(payload, jwk, {
      header: {
        alg: "ES256K",
        typ: "JWT",
      },
    });
    mockVerifyJwt.mockResolvedValue(undefined as never);
    mockDecodeJWT.mockReturnValue({} as never);
    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        registry: RPC_ADDRESS,
        rpcUrl: RPC_PROVIDER,
      },
    };
    await expect(verifyDidAuthRequest(jwt, optsVerify)).rejects.toThrow(
      DidAuthErrors.NO_AUDIENCE
    );
    jest.clearAllMocks();
  });

  it("should return a string audience", async () => {
    expect.assertions(3);
    const RPC_PROVIDER =
      "https://ropsten.infura.io/v3/f03e98e0dc2b855be647c39abe984fcf";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
    const payload = {
      aud: "did:vid:0x0abcd",
    };
    const jwt = JWT.sign(payload, jwk, {
      header: {
        alg: "ES256K",
        typ: "JWT",
      },
    });
    mockVerifyJwt.mockResolvedValue({ payload } as never);
    mockDecodeJWT.mockReturnValue({ payload } as never);
    const optsVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        registry: RPC_ADDRESS,
        rpcUrl: RPC_PROVIDER,
      },
    };
    const response = await verifyDidAuthRequest(jwt, optsVerify);
    expect(response).toBeDefined();
    expect(response.payload).toBeDefined();
    expect(response.payload).toMatchObject(payload);
    jest.clearAllMocks();
  });
});
