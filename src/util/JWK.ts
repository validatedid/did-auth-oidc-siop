import { ec as EC } from "elliptic";
import SHA from "sha.js";
import { JWK, DidAuth } from "../interfaces";
import { base64urlEncodeBuffer } from "./Util";

const getJWK = (hexPrivateKey: string, kid?: string): JWK.JWKECKey => {
  const ec = new EC("secp256k1");
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();
  return {
    kid,
    kty: DidAuth.DidAuthKeyType.EC,
    crv: DidAuth.DidAuthKeyCurve.SECP256k1,
    x: pubPoint.getX().toString("hex"),
    y: pubPoint.getY().toString("hex"),
  };
};

const getThumbprint = (hexPrivateKey: string): string => {
  const jwk = getJWK(hexPrivateKey);
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

export { getThumbprint, getJWK };
