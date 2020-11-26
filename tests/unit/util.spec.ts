import { JWK } from "jose";
import {
  DidAuthKeyCurve,
  DidAuthKeyType,
} from "../../src/interfaces/DIDAuth.types";
import {
  getNonce,
  getState,
  prefixWith0x,
  getDIDFromKey,
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

  it("compute a DID from an jwk key", () => {
    expect.assertions(2);
    const key = JWK.generateSync(DidAuthKeyType.EC, DidAuthKeyCurve.SECP256k1, {
      use: "sig",
    });
    const did = getDIDFromKey(key);
    expect(did).toBeDefined();
    expect(did).toContain(`did:vid:`);
  });
});
