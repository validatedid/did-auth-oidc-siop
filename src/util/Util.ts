import { v4 as uuidv4 } from "uuid";
import axios, { AxiosResponse } from "axios";
import { ethers } from "ethers";
import { decodeJWT } from "did-jwt";
import { JWK, Errors } from "../interfaces";

export const prefixWith0x = (key: string): string => {
  return key.startsWith("0x") ? key : `0x${key}`;
};

function getNonce(): string {
  return uuidv4();
}

const generateRandomString = (length = 6) =>
  Math.random().toString(20).substr(2, length);

function getState(): string {
  return generateRandomString();
}

function toHex(data: string): string {
  return Buffer.from(data, "base64").toString("hex");
}

function getEthWallet(key: JWK.Key): ethers.Wallet {
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

const getAudience = (jwt: string): string | undefined => {
  const { payload } = decodeJWT(jwt);
  if (!payload) throw new Error(Errors.NO_AUDIENCE);
  if (!payload.aud) return undefined;
  if (Array.isArray(payload.aud)) throw new Error(Errors.INVALID_AUDIENCE);
  return payload.aud;
};

export {
  getNonce,
  getState,
  getAudience,
  getDIDFromKey,
  getHexPrivateKey,
  doPostCallWithToken,
  base64urlEncodeBuffer,
};
