import { v4 as uuidv4 } from "uuid";
import axios, { AxiosResponse } from "axios";
import { ethers } from "ethers";
import { ec as EC } from "elliptic";
import * as JWK from "./JWK";
import DidAuthErrors from "../Errors";

export const prefixWith0x = (key: string): string => {
  return key.startsWith("0x") ? key : `0x${key}`;
};

function getNonce(): string {
  return uuidv4();
}

function toHex(data: string): string {
  return Buffer.from(data, "base64").toString("hex");
}

function getEthWallet(key: JWK.Key): ethers.Wallet {
  if (!key.d) throw new Error(DidAuthErrors.BAD_KEY_FORMAT);
  return new ethers.Wallet(prefixWith0x(toHex(key.d)));
}

function getHexPrivateKey(key: JWK.Key): string {
  return getEthWallet(key).privateKey;
}

function getEthAddress(key: JWK.ECKey): string {
  return getEthWallet(key).address;
}

function getDIDFromKey(key: JWK.ECKey): string {
  return `did:vid:${getEthAddress(key)}`;
}

const fromBase64 = (base64: string) => {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

const base64urlEncodeBuffer = (buf: {
  toString: (arg0: "base64") => string;
}): string => {
  return fromBase64(buf.toString("base64"));
};

function getECKeyfromHexPrivateKey(
  hexPrivateKey: string
): { x: string; y: string } {
  const ec = new EC("secp256k1");
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();
  return {
    x: pubPoint.getX().toString("hex"),
    y: pubPoint.getY().toString("hex"),
  };
}

async function doPostCallWithToken(
  url: string,
  data: unknown,
  token: string
): Promise<AxiosResponse> {
  const config = {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };
  const response = await axios.post(url, data, config);
  return response;
}

export {
  getNonce,
  getDIDFromKey,
  getHexPrivateKey,
  doPostCallWithToken,
  base64urlEncodeBuffer,
  getECKeyfromHexPrivateKey,
};
