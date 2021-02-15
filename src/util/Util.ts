import SHA from "sha.js";
import base58 from "bs58";
import { ec as EC } from "elliptic";
import { JWK } from "jose/types";
import base64url from "base64url";
import VidDidResolver from "@validatedid/vid-did-resolver";
import { decodeJwt, EcdsaSignature } from "@validatedid/did-jwt";
import { Resolver } from "did-resolver";
import axios, { AxiosResponse } from "axios";
import { ethers, utils } from "ethers";
import { keyUtils } from "@transmute/did-key-ed25519";
import parseJwk from "jose/jwk/parse";
import jwtVerify from "jose/jwt/verify";

import { DidAuthErrors } from "../interfaces";
import {
  DidAuthKeyAlgorithm,
  DidAuthRequestPayload,
  DidAuthResponseIss,
  DidAuthResponsePayload,
  InternalVerification,
  RegistrationJwksUri,
} from "../interfaces/DIDAuth.types";
import { Resolvable } from "../interfaces/JWT";
import { DIDDocument, VerificationMethod } from "../interfaces/oidcSsi";

export const prefixWith0x = (key: string): string =>
  key.startsWith("0x") ? key : `0x${key}`;

const fromBase64 = (base64: string) =>
  base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

const base64urlEncodeBuffer = (buf: {
  toString: (arg0: "base64") => string;
}): string => fromBase64(buf.toString("base64"));

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

function getEthWallet(key: JWK): ethers.Wallet {
  return new ethers.Wallet(prefixWith0x(toHex(key.d)));
}

function getHexPrivateKey(key: JWK): string {
  return getEthWallet(key).privateKey;
}

function getEthAddress(key: JWK): string {
  return getEthWallet(key).address;
}

function getDIDFromKey(key: JWK): string {
  return `did:vid:${getEthAddress(key)}`;
}

async function doPostCallWithToken(
  url: string,
  data: unknown,
  token: string
): Promise<AxiosResponse> {
  const conf = {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  };
  try {
    const response = await axios.post(url, data, conf);
    return response;
  } catch (error) {
    throw new Error(
      `${DidAuthErrors.ERROR_ON_POST_CALL}${(error as Error).message}`
    );
  }
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
    return (payload as DidAuthResponsePayload).did;
  return payload.iss;
};

const getUrlResolver = async (
  jwt: string,
  internalVerification: InternalVerification
): Promise<Resolvable | Resolver | string> => {
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

const hasJwksUri = (payload: DidAuthRequestPayload): boolean => {
  if (!payload) return false;
  if (
    !payload.registration ||
    !(payload.registration as RegistrationJwksUri).jwks_uri
  )
    return false;
  return true;
};

const DidMatchFromJwksUri = (
  payload: DidAuthRequestPayload,
  issuerDid: string
): boolean => {
  const jwksUri = (payload.registration as RegistrationJwksUri).jwks_uri;
  return jwksUri.includes(issuerDid);
};

const getVerificationMethod = (
  kid: string,
  didDoc: DIDDocument
): VerificationMethod => {
  if (
    !didDoc ||
    !didDoc.verificationMethod ||
    didDoc.verificationMethod.length < 1
  )
    throw new Error(DidAuthErrors.ERROR_RETRIEVING_VERIFICATION_METHOD);
  const { verificationMethod } = didDoc;
  // kid can be "kid": "H7j7N4Phx2U1JQZ2SBjczz2omRjnMgT8c2gjDBv2Bf0="
  // or "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1
  // and id always contains did:xxx:yyy#kid
  return verificationMethod.find((elem) =>
    kid.includes("did:") || kid.startsWith("#")
      ? elem.id === kid
      : elem.id.split("#")[1] === kid
  );
};

const extractPublicKeyBytes = (
  vm: VerificationMethod
): string | { x: string; y: string } => {
  if (vm.publicKeyBase58) {
    return base58.decode(vm.publicKeyBase58).toString("hex");
  }

  if (vm.publicKeyJwk) {
    return { x: vm.publicKeyJwk.x, y: vm.publicKeyJwk.y };
  }
  throw new Error("No public key found!");
};

function toSignatureObject(signature: string): EcdsaSignature {
  const rawsig: Buffer = base64url.toBuffer(signature);
  if (rawsig.length !== 64 && rawsig.length !== 65) {
    throw new Error("wrong signature length");
  }

  const r: string = rawsig.slice(0, 32).toString("hex");
  const s: string = rawsig.slice(32, 64).toString("hex");
  const sigObj: EcdsaSignature = { r, s };

  return sigObj;
}
const verifyES256K = (
  jwt: string,
  verificationMethod: VerificationMethod
): boolean => {
  try {
    const publicKey = extractPublicKeyBytes(verificationMethod);
    const secp256k1 = new EC("secp256k1");
    const { data, signature } = decodeJwt(jwt);
    const hash = SHA("sha256").update(data).digest();
    const sigObj = toSignatureObject(signature);
    return secp256k1.keyFromPublic(publicKey, "hex").verify(hash, sigObj);
  } catch (err) {
    return false;
  }
};

const verifyEDDSA = async (
  jwt: string,
  verificationMethod: VerificationMethod
): Promise<boolean> => {
  try {
    let publicKey: JWK;
    if (verificationMethod.publicKeyBase58)
      publicKey = keyUtils.publicKeyJwkFromPublicKeyBase58(
        verificationMethod.publicKeyBase58
      );
    if (verificationMethod.publicKeyJwk)
      publicKey = verificationMethod.publicKeyJwk;
    const result = await jwtVerify(
      jwt,
      await parseJwk(publicKey, DidAuthKeyAlgorithm.EDDSA)
    );
    if (!result || !result.payload)
      throw Error(DidAuthErrors.ERROR_VERIFYING_SIGNATURE);
    return true;
  } catch (err) {
    return false;
  }
};

const verifySignatureFromVerificationMethod = async (
  jwt: string,
  verificationMethod: VerificationMethod
): Promise<boolean> => {
  const { header } = decodeJwt(jwt);
  return header.alg === DidAuthKeyAlgorithm.EDDSA
    ? verifyEDDSA(jwt, verificationMethod)
    : verifyES256K(jwt, verificationMethod);
};

export {
  getNonce,
  getState,
  hasJwksUri,
  getAudience,
  getIssuerDid,
  getDIDFromKey,
  getUrlResolver,
  getHexPrivateKey,
  DidMatchFromJwksUri,
  doPostCallWithToken,
  base64urlEncodeBuffer,
  getVerificationMethod,
  verifySignatureFromVerificationMethod,
};
