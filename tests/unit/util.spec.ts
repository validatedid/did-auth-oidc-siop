import { getNonce, getState, prefixWith0x } from "../../src/util/Util";

describe("unit tests", () => {
  it("should prefix '0x' to a given string that does not starts with '0x'", () => {
    expect.assertions(1);
    const input = "1234";
    const response = prefixWith0x(input);
    expect(response).toStrictEqual(`0x${input}`);
  });

  it("should not add prefix '0x' to a given string that starts with '0x'", () => {
    expect.assertions(1);
    const input = "0x1234";
    const response = prefixWith0x(input);
    expect(response).toStrictEqual(input);
  });

  it("should compute a state", () => {
    expect.assertions(1);
    const state = getState();
    expect(state).toBeDefined();
  });

  it("should compute a nonce from 'Hello World'", () => {
    expect.assertions(1);
    const nonce = getNonce("Hello World");
    expect(nonce).toStrictEqual("pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4");
  });

  it("should compute an nonce from a state", () => {
    expect.assertions(1);
    const state = getState();
    const nonce = getNonce(state);
    expect(nonce).toBeDefined();
  });
});
