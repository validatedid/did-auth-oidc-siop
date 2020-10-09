import { v4 as uuidv4 } from "uuid";
import axios from "axios";
import { ethers } from "ethers";
import { ec as EC } from "elliptic";
import * as JWK from "./JWK";

function getNonce(): string {
  return uuidv4();
}

function toHex(data: string): string {
  return Buffer.from(data, "base64").toString("hex");
}

function getEthWallet(key: JWK.Key): ethers.Wallet {
  return new ethers.Wallet(toHex(key.d as string));
}

function getHexPrivateKey(key: JWK.Key): string {
  return getEthWallet(key).privateKey;
}

function getEthAddress(key: JWK.ECKey): string {
  return getEthWallet(key).address;
}

function getDIDFromKey(key: JWK.ECKey): string {
  return `did:ebsi:${getEthAddress(key)}`;
}

const fromBase64 = (base64: string) => {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

const base64urlEncodeBuffer = (buf: { toString: (arg0: string) => any }) => {
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
  data: any,
  token: string
): Promise<any> {
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
