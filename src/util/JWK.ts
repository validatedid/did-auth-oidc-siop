import { ec as EC } from "elliptic";
import SHA from "sha.js";
import { JWK, types } from "../interfaces";
import { base64urlEncodeBuffer } from "./Util";

const getPublicJWKFromPublicHex = (
  hexPublicKey: string,
  kid?: string
): JWK.JWKECKey => {
  const ec = new EC("secp256k1");
  const key = ec.keyFromPublic(hexPublicKey.replace("0x", ""), "hex");
  const pubPoint = key.getPublic();
  return {
    kid,
    kty: types.DidAuthKeyType.EC,
    crv: types.DidAuthKeyCurve.SECP256k1,
    x: pubPoint.getX().toString("hex"),
    y: pubPoint.getY().toString("hex"),
  };
};

const getPublicJWKFromPrivateHex = (
  hexPrivateKey: string,
  kid?: string
): JWK.JWKECKey => {
  const ec = new EC("secp256k1");
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();
  return {
    kid,
    kty: types.DidAuthKeyType.EC,
    crv: types.DidAuthKeyCurve.SECP256k1,
    x: pubPoint.getX().toString("hex"),
    y: pubPoint.getY().toString("hex"),
  };
};

const getThumbprint = (hexPrivateKey: string): string => {
  const jwk = getPublicJWKFromPrivateHex(hexPrivateKey);
  const fields = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
  const buff = SHA("sha256").update(JSON.stringify(fields)).digest();
  const thumbprint = base64urlEncodeBuffer(buff);

  return thumbprint;
};

export { getThumbprint, getPublicJWKFromPrivateHex, getPublicJWKFromPublicHex };
