import SHA from "sha.js";
import VidDidResolver from "@validatedid/vid-did-resolver";
import { decodeJwt } from "@validatedid/did-jwt";
import { Resolver } from "did-resolver";
import axios, { AxiosResponse } from "axios";
import { ethers, utils } from "ethers";
import { JWK, DidAuthErrors } from "../interfaces";
import {
  DidAuthResponseIss,
  DidAuthResponsePayload,
  InternalVerification,
} from "../interfaces/DIDAuth.types";
import { Resolvable } from "../interfaces/JWT";

export const prefixWith0x = (key: string): string => {
  return key.startsWith("0x") ? key : `0x${key}`;
};

const fromBase64 = (base64: string) => {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};

const base64urlEncodeBuffer = (buf: {
  toString: (arg0: "base64") => string;
}): string => {
  return fromBase64(buf.toString("base64"));
};

function getNonce(input: string): string {
  const buff = SHA("sha256").update(input).digest();
  return base64urlEncodeBuffer(buff);
}

function getState(): string {
  const randomNumber = ethers.BigNumber.from(utils.randomBytes(12));
  return utils.hexlify(randomNumber).replace("0x", "");
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
  const { payload } = decodeJwt(jwt);
  if (!payload) throw new Error(DidAuthErrors.NO_AUDIENCE);
  if (!payload.aud) return undefined;
  if (Array.isArray(payload.aud))
    throw new Error(DidAuthErrors.INVALID_AUDIENCE);
  return payload.aud;
};

const getIssuerDid = (jwt: string): string => {
  const { payload } = decodeJwt(jwt);
  if (!payload || !payload.iss) throw new Error(DidAuthErrors.NO_ISS_DID);
  if (payload.iss === DidAuthResponseIss.SELF_ISSUE)
    return ((payload as unknown) as DidAuthResponsePayload).did;
  return payload.iss;
};

const getUrlResolver = async (
  jwt: string,
  internalVerification: InternalVerification
): Promise<Resolvable | string> => {
  try {
    if (!internalVerification.didUrlResolver)
      throw new Error(DidAuthErrors.BAD_INTERNAL_VERIFICATION_PARAMS);
    // check if the token issuer DID can be resolved
    await axios.get(
      `${internalVerification.didUrlResolver}/${getIssuerDid(jwt)}`
    );
    return internalVerification.didUrlResolver;
  } catch (error) {
    if (!internalVerification.registry || !internalVerification.rpcUrl)
      throw new Error(DidAuthErrors.BAD_INTERNAL_VERIFICATION_PARAMS);
    return new Resolver(
      VidDidResolver.getResolver({
        rpcUrl: internalVerification.rpcUrl,
        registry: internalVerification.registry,
      })
    );
  }
};

export {
  getNonce,
  getState,
  getAudience,
  getDIDFromKey,
  getUrlResolver,
  getHexPrivateKey,
  doPostCallWithToken,
  base64urlEncodeBuffer,
};
