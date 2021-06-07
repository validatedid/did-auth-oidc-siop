import crypto from "crypto";
import fromKeyLike from "jose/jwk/from_key_like";
import { DidAuthKeyCurve } from "../../src/interfaces/DIDAuth.types";
import {
  getNonce,
  getState,
  prefixWith0x,
  getDIDFromKey,
  getNetworkFromDid,
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
});
