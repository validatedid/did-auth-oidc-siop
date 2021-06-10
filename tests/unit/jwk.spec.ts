import { getPublicJWKFromPublicHex } from "../../src/util/JWK";

describe("jwk tests should", () => {
  it("return a jwk from a hex public key", () => {
    expect.assertions(1);
    const publicKeyHex =
      "0492effe517268785a80b98fbe60e4a712ee096b9c5224ad23a61ff129bdb341a08936c9d407f5b089ff635f85c305c105499bd1b668814a23e7d9865edd4d665a";
    const jwk = getPublicJWKFromPublicHex(publicKeyHex);
    const expectedJwk = {
      kty: "EC",
      crv: "secp256k1",
      x: "ku_-UXJoeFqAuY--YOSnEu4Ja5xSJK0jph_xKb2zQaA",
      y: "iTbJ1Af1sIn_Y1-FwwXBBUmb0bZogUoj59mGXt1NZlo",
    };
    expect(jwk).toMatchObject(expectedJwk);
  });

  it("return a jwk from a hex public key starting with 0x", () => {
    expect.assertions(1);
    const publicKeyHex =
      "0x0492effe517268785a80b98fbe60e4a712ee096b9c5224ad23a61ff129bdb341a08936c9d407f5b089ff635f85c305c105499bd1b668814a23e7d9865edd4d665a";
    const jwk = getPublicJWKFromPublicHex(publicKeyHex);
    const expectedJwk = {
      kty: "EC",
      crv: "secp256k1",
      x: "ku_-UXJoeFqAuY--YOSnEu4Ja5xSJK0jph_xKb2zQaA",
      y: "iTbJ1Af1sIn_Y1-FwwXBBUmb0bZogUoj59mGXt1NZlo",
    };
    expect(jwk).toMatchObject(expectedJwk);
  });

  it("return a jwk from a hex public key and kid", () => {
    expect.assertions(1);
    const publicKeyHex =
      "0492effe517268785a80b98fbe60e4a712ee096b9c5224ad23a61ff129bdb341a08936c9d407f5b089ff635f85c305c105499bd1b668814a23e7d9865edd4d665a";
    const kid = "did:ethr:0x4B59e08A51C7CdF9017c58E8Bf767db6d34daD7E#keys-1";
    const jwk = getPublicJWKFromPublicHex(publicKeyHex, kid);
    const expectedJwk = {
      kid,
      kty: "EC",
      crv: "secp256k1",
      x: "ku_-UXJoeFqAuY--YOSnEu4Ja5xSJK0jph_xKb2zQaA",
      y: "iTbJ1Af1sIn_Y1-FwwXBBUmb0bZogUoj59mGXt1NZlo",
    };
    expect(jwk).toMatchObject(expectedJwk);
  });

  it("return a jwk from a hex public key starting with 0x and kid", () => {
    expect.assertions(1);
    const publicKeyHex =
      "0x0492effe517268785a80b98fbe60e4a712ee096b9c5224ad23a61ff129bdb341a08936c9d407f5b089ff635f85c305c105499bd1b668814a23e7d9865edd4d665a";
    const kid = "did:ethr:0x4B59e08A51C7CdF9017c58E8Bf767db6d34daD7E#keys-1";
    const jwk = getPublicJWKFromPublicHex(publicKeyHex, kid);
    const expectedJwk = {
      kid,
      kty: "EC",
      crv: "secp256k1",
      x: "ku_-UXJoeFqAuY--YOSnEu4Ja5xSJK0jph_xKb2zQaA",
      y: "iTbJ1Af1sIn_Y1-FwwXBBUmb0bZogUoj59mGXt1NZlo",
    };
    expect(jwk).toMatchObject(expectedJwk);
  });
});
