import { keyUtils } from "@transmute/did-key-ed25519";
import bs58 from "bs58";
import { ec as EC } from "elliptic";
import { JWK } from "jose";
import SHA from "sha.js";
import { Base64 } from "js-base64";
import { types } from "../interfaces";
// eslint-disable-next-line import/no-cycle
import { base64urlEncodeBuffer } from "./Util";

const getPublicJWKFromPublicHexDidKey = (
  hexPublicKey: string,
  kid?: string
): JWK => {
  const ec = new EC("ed25519");
  // Convert the key to base58 in order to get the jwk with another method from library keyUtils
  const publicKeyBase58 = keyUtils.publicKeyBase58FromPublicKeyHex(
    hexPublicKey
  ) as string;
  const pubJwk = keyUtils.publicKeyJwkFromPublicKeyBase58(publicKeyBase58);
  return pubJwk;
};

const getPublicJWKFromPublicHex = (
  hexPublicKey: string,
  kid?: string,
  method?: string
): JWK => {
  if (method && method.includes("did:key:z6Mk"))
    return getPublicJWKFromPublicHexDidKey(hexPublicKey, kid);
  const ec = new EC("secp256k1");
  const key = ec.keyFromPublic(hexPublicKey.replace("0x", ""), "hex");
  const pubPoint = key.getPublic();
  return {
    kid,
    kty: types.DidAuthKeyType.EC,
    crv: types.DidAuthKeyCurve.SECP256k1,
    x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
    y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
  };
};

const getPublicJWKFromPrivateHexDidKey = (
  hexPrivateKey: string,
  kid?: string
): JWK => {
  const ec = new EC("ed25519");
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();
  return {
    kid,
    kty: types.DidAuthKeyType.EC,
    crv: types.DidAuthKeyCurve.ED25519,
    x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
    y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
  };
};

const getPublicJWKFromPrivateHex = (
  hexPrivateKey: string,
  kid?: string,
  method?: string
): JWK => {
  if (method && method.includes("did:key:z6Mk"))
    return getPublicJWKFromPrivateHexDidKey(hexPrivateKey, kid);
  const ec = new EC("secp256k1");
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();
  return {
    kid,
    kty: types.DidAuthKeyType.EC,
    crv: types.DidAuthKeyCurve.SECP256k1,
    x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
    y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
  };
};

const getThumbprintFromJwk = (jwk: JWK): string => {
  const fields = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
  const buff = SHA("sha256").update(JSON.stringify(fields)).digest();
  return base64urlEncodeBuffer(buff);
};

// from fingerprintFromPublicKey function in @transmute/Ed25519KeyPair
const getThumbprintFromJwkDidKey = (jwk: JWK): string => {
  // ed25519 cryptonyms are multicodec encoded values, specifically:
  // (multicodec ed25519-pub 0xed01 + key bytes)
  const pubkeyBytes = bs58.decode(
    keyUtils.publicKeyBase58FromPublicKeyJwk(jwk)
  );
  const buffer = new Uint8Array(2 + pubkeyBytes.length);
  buffer[0] = 0xed;
  buffer[1] = 0x01;
  buffer.set(pubkeyBytes, 2);
  // prefix with `z` to indicate multi-base base58btc encoding
  return `z${bs58.encode(buffer)}`;
};

const getThumbprint = (hexPrivateKey: string, method: string): string => {
  const jwk = method.includes("did:key:z6Mk")
    ? getPublicJWKFromPrivateHexDidKey(hexPrivateKey)
    : getPublicJWKFromPrivateHex(hexPrivateKey);
  return method.includes("did:key:z6Mk")
    ? getThumbprintFromJwkDidKey(jwk)
    : getThumbprintFromJwk(jwk);
};

export {
  getThumbprint,
  getPublicJWKFromPrivateHex,
  getPublicJWKFromPublicHex,
  getPublicJWKFromPrivateHexDidKey,
  getThumbprintFromJwk,
  getThumbprintFromJwkDidKey,
};
