import crypto from "crypto";
import fromKeyLike from "jose/jwk/from_key_like";
import { VerificationMethod } from "did-resolver";
import { DidAuthKeyCurve } from "../../src/interfaces/DIDAuth.types";
import {
  getNonce,
  getState,
  prefixWith0x,
  getDIDFromKey,
  getNetworkFromDid,
  extractPublicKeyBytes,
} from "../../src/util/Util";

describe("unit tests should", () => {
  it("prefix '0x' to a given string that does not starts with '0x'", () => {
    expect.assertions(1);
    const input = "1234";
    const response = prefixWith0x(input);
    expect(response).toStrictEqual(`0x${input}`);
  });

  it("not add prefix '0x' to a given string that starts with '0x'", () => {
    expect.assertions(1);
    const input = "0x1234";
    const response = prefixWith0x(input);
    expect(response).toStrictEqual(input);
  });

  it("compute a state", () => {
    expect.assertions(1);
    const state = getState();
    expect(state).toBeDefined();
  });

  it("compute a nonce from 'Hello World'", () => {
    expect.assertions(1);
    const nonce = getNonce("Hello World");
    expect(nonce).toStrictEqual("pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4");
  });

  it("compute an nonce from a state", () => {
    expect.assertions(1);
    const state = getState();
    const nonce = getNonce(state);
    expect(nonce).toBeDefined();
  });

  it("compute a DID from an jwk key", async () => {
    expect.assertions(2);
    const key = crypto.generateKeyPairSync("ec", {
      namedCurve: DidAuthKeyCurve.SECP256k1,
    });
    const privateJwk = await fromKeyLike(key.privateKey);

    const did = getDIDFromKey(privateJwk);
    expect(did).toBeDefined();
    expect(did).toContain(`did:ethr:`);
  });

  it("return the network name from the did", () => {
    expect.assertions(5);
    const network = getNetworkFromDid(
      "did:ethr:mainnet:0xabcabc03e98e0dc2b855be647c39abe984193675"
    );
    const network2 = getNetworkFromDid(
      "did:ethr:0xabcabc03e98e0dc2b855be647c39abe984193675"
    );
    const network3 = getNetworkFromDid(
      "did:ethr:development:0xabcabc03e98e0dc2b855be647c39abe984193675"
    );
    const network4 = getNetworkFromDid(
      "did:ethr:myprivatenet:0xabcabc03e98e0dc2b855be647c39abe984193675"
    );
    const network5 = getNetworkFromDid(
      "did:ethr:rsk:testnet:0xabcabc03e98e0dc2b855be647c39abe984193675"
    );

    expect(network).toBe("mainnet");
    expect(network2).toBe("mainnet");
    expect(network3).toBe("development");
    expect(network4).toBe("myprivatenet");
    expect(network5).toBe("rsk:testnet");
  });

  it("should convert the x and y received in base64 to hex", () => {
    expect.assertions(2);
    const verificationMethodInBase64: VerificationMethod = {
      id:
        "did:ethr:0xFE2837BC57b0b59053A99Fc3D268B505D60fCD7F#wB0xotWlUw39tHX7bMNOMA8pbpvfoh/ex4wj9kOGFq4=",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:ethr:0xFE2837BC57b0b59053A99Fc3D268B505D60fCD7F",
      publicKeyJwk: {
        kty: "EC",
        crv: "secp256k1",
        x: "OJYHK0yvCRFBK54BxLx_fONOFzOCJAaGrsmU4sRiuac",
        y: "MnF9aYSat0OGWgfOjoNak9I24jfeasbrRZiMnAlRgyM",
        kid: "wB0xotWlUw39tHX7bMNOMA8pbpvfoh/ex4wj9kOGFq4=",
      },
    };
    const extractKeys = extractPublicKeyBytes(verificationMethodInBase64) as {
      x: string;
      y: string;
    };

    expect(extractKeys.x).toBe(
      "3896072b4caf0911412b9e01c4bc7f7ce34e173382240686aec994e2c462b9a7"
    );
    expect(extractKeys.y).toBe(
      "32717d69849ab743865a07ce8e835a93d236e237de6ac6eb45988c9c09518323"
    );
  });

  it("should return the x and y received in hex", () => {
    expect.assertions(2);
    const verificationMethodInHex: VerificationMethod = {
      id:
        "did:ethr:0xFE2837BC57b0b59053A99Fc3D268B505D60fCD7F#wB0xotWlUw39tHX7bMNOMA8pbpvfoh/ex4wj9kOGFq4=",
      type: "EcdsaSecp256k1VerificationKey2019",
      controller: "did:ethr:0xFE2837BC57b0b59053A99Fc3D268B505D60fCD7F",
      publicKeyJwk: {
        kty: "EC",
        crv: "secp256k1",
        x: "64ad605fdd256896a3d7b0904e137e667e8f9fd98f448521e1a8ee9f4bc0d9c5",
        y: "3ef7b0062ad9f4dd47ce614bebde0e7af123183a8ce4b2a9500c76fda57fd6e8",
        kid: "F28Mu0OVC70ZSBxx4Z4Rqci2gjFSTdZcdT+nOz9ekSE=",
      },
    };
    const extractKeys = extractPublicKeyBytes(verificationMethodInHex) as {
      x: string;
      y: string;
    };

    expect(extractKeys.x).toBe(
      "64ad605fdd256896a3d7b0904e137e667e8f9fd98f448521e1a8ee9f4bc0d9c5"
    );
    expect(extractKeys.y).toBe(
      "3ef7b0062ad9f4dd47ce614bebde0e7af123183a8ce4b2a9500c76fda57fd6e8"
    );
  });
});
