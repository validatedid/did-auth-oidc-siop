import { JWT, JWK } from "jose";
import { v4 as uuidv4 } from "uuid";
import axios, { AxiosResponse } from "axios";
import moment from "moment";
import { ethers } from "ethers";

import base58 from "bs58";
import { DidAuthErrors, JWTClaims, DidAuthUtil, DidAuthTypes } from "../src";
import { prefixWith0x } from "../src/util/Util";
import {
  DidAuthKeyCurve,
  DidAuthKeyType,
} from "../src/interfaces/DIDAuth.types";
import { getPublicJWKFromPrivateHex, getThumbprint } from "../src/util/JWK";
import { JWTHeader, JWTPayload } from "../src/interfaces/JWT";
import { JWKECKey, VidJWKECKey } from "../src/interfaces/JWK";
import {
  DID_DOCUMENT_PUBKEY_B58,
  DID_DOCUMENT_PUBKEY_JWK,
} from "./data/mockedData";
import { DIDDocument } from "../src/interfaces/oidcSsi";

export interface TESTKEY {
  key: JWK.ECKey;
  did: string;
  didDoc?: DIDDocument;
}

enum TokenType {
  bearer = "Bearer",
}

interface AccessTokenResponseBody {
  accessToken: string;
  tokenType: TokenType.bearer;
  expiresIn: number; // 15 minutes
  issuedAt: number;
}

export function generateTestKey(kty: string): TESTKEY {
  let key: JWK.ECKey;

  switch (kty) {
    case DidAuthKeyType.EC:
      key = JWK.generateSync(DidAuthKeyType.EC, DidAuthKeyCurve.SECP256k1, {
        use: "sig",
      });
      break;
    default:
      throw new Error(DidAuthErrors.NO_ALG_SUPPORTED);
  }

  const did = DidAuthUtil.getDIDFromKey(key);

  return {
    key,
    did,
  };
}

export interface IEnterpriseAuthZToken extends JWTClaims {
  sub?: string;
  did: string;
  aud: string;
  nonce: string;
}

export interface LegalEntityAuthNToken extends JWTClaims {
  iss: string; // legal entity name identifier
  aud: string; // RP Application Name. usually vidchain-wallet
  iat: number;
  exp: number;
  nonce: string;
  apiKey: string;
  callbackUrl?: string; // Entity url to send notifications
  image?: string; // base64 encoded image data
  icon?: string; // base64 encoded image icon data
}

export interface LegalEntityTestAuthN {
  iss: string; // legal entity name identifier
  aud: string; // RP Application Name. usually vidchain-wallet
  iat: number;
  exp: number;
  nonce: string;
  callbackUrl?: string; // Entity url to send notifications
  image?: string; // base64 encoded image data
  icon?: string; // base64 encoded image icon data
}

export const mockedKeyAndDid = (): {
  hexPrivateKey: string;
  did: string;
  jwk: JWK.ECKey;
  hexPublicKey: string;
} => {
  // generate a new keypair
  const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
  const hexPrivateKey = Buffer.from(jwk.d, "base64").toString("hex");
  const wallet: ethers.Wallet = new ethers.Wallet(prefixWith0x(hexPrivateKey));
  const did = `did:vid:${wallet.address}`;
  const hexPublicKey = wallet.publicKey;
  return { hexPrivateKey, did, jwk, hexPublicKey };
};

const mockedEntityAuthNToken = (
  enterpiseName?: string
): {
  jwt: string;
  jwk: JWK.ECKey;
  did: string;
  hexPrivateKey: string;
  hexPublicKey: string;
} => {
  // generate a new keypair
  const { did, jwk, hexPrivateKey, hexPublicKey } = mockedKeyAndDid();

  const payload: LegalEntityTestAuthN = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "minutes").unix(),
    nonce: uuidv4(),
  };

  const jwt = JWT.sign(payload, jwk, {
    header: {
      alg: "ES256K",
      typ: "JWT",
    },
  });
  return { jwt, jwk, did, hexPrivateKey, hexPublicKey };
};

const testEntityAuthNToken = (enterpiseName?: string): { jwt: string } => {
  const payload: LegalEntityTestAuthN = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "minutes").unix(),
    nonce: uuidv4(),
  };

  const jwt = Buffer.from(JSON.stringify(payload)).toString("base64");
  return { jwt };
};

export function getEnterpriseDID(token: string): string {
  const { payload } = JWT.decode(token, { complete: true });

  return (payload as IEnterpriseAuthZToken).did;
}

async function doPostCall(url: string, data: unknown): Promise<AxiosResponse> {
  const response = await axios.post(url, data);
  return response;
}

interface ApiKeyStruct {
  type: string;
  authenticationKey: string;
}

const getEntityAuthNToken = async (
  enterpiseName?: string
): Promise<{ jwt: string }> => {
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "http://localhost:9000";
  // get entity API Key
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/api/v1/authentication-keys`,
    { iss: enterpiseName || "Test Legal Entity" }
  );
  if (!result || !result.data)
    throw new Error("Authentication Keys not generated.");
  const apiKeyStruct = result.data as ApiKeyStruct;
  if (!apiKeyStruct.type || !apiKeyStruct.authenticationKey)
    throw new Error("Authentication Keys not generated.");

  const payload: LegalEntityAuthNToken = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "minutes").unix(),
    nonce: uuidv4(),
    apiKey: apiKeyStruct.authenticationKey,
  };

  const jwt = Buffer.from(JSON.stringify(payload)).toString("base64");
  return { jwt };
};

export const getLegalEntityAuthZToken = async (
  enterpiseName?: string
): Promise<{
  jwt: string;
  did: string;
}> => {
  const auth = await getEntityAuthNToken(enterpiseName);
  const payload = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: auth.jwt,
    scope: "vidchain profile entity",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "http://localhost:9000";
  // Create and sign JWT
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/api/v1/sessions`,
    payload
  );
  const { accessToken } = result.data as AccessTokenResponseBody;

  return {
    jwt: accessToken,
    did: getEnterpriseDID(accessToken),
  };
};

export async function getLegalEntityTestAuthZToken(
  enterpiseName?: string
): Promise<{
  jwt: string;
  did: string;
}> {
  const testAuth = testEntityAuthNToken(enterpiseName);
  const payload = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: testAuth.jwt,
    scope: "vidchain profile test entity",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "http://localhost:9000";
  // Create and sign JWT
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/api/v1/sessions`,
    payload
  );
  const { accessToken } = result.data as AccessTokenResponseBody;

  return {
    jwt: accessToken,
    did: getEnterpriseDID(accessToken),
  };
}

export function mockedGetEnterpriseAuthToken(
  enterpriseName?: string
): {
  jwt: string;
  did: string;
  jwk: JWK.ECKey;
  hexPrivateKey: string;
  hexPublicKey: string;
} {
  const testAuth = mockedEntityAuthNToken(enterpriseName);
  const payload = JWT.decode(testAuth.jwt) as JWTPayload;

  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,
    aud: payload?.iss ? payload.iss : "Test Legal Entity",
    nonce: ((payload as unknown) as IEnterpriseAuthZToken).nonce,
  };

  const vidPayload = {
    ...inputPayload,
    ...{
      sub: payload.iss, // Should be the id of the app that is requesting the token
      iat: moment().unix(),
      exp: moment().add(15, "minutes").unix(),
      aud: "vidchain-api",
    },
  };

  const jwt = JWT.sign(vidPayload, testAuth.jwk, {
    header: {
      alg: "ES256K",
      typ: "JWT",
    },
  });

  return {
    jwt,
    did: testAuth.did,
    jwk: testAuth.jwk,
    hexPrivateKey: testAuth.hexPrivateKey,
    hexPublicKey: testAuth.hexPublicKey,
  };
}

export interface InputToken {
  enterpiseName?: string;
  nonce?: string;
}

export const mockedIdToken = (
  inputToken: InputToken
): {
  jwt: string;
  did: string;
  jwk: JWK.ECKey;
  idToken: string;
  hexPublicKey: string;
  header: JWTHeader;
  payload: DidAuthTypes.DidAuthResponsePayload;
} => {
  const {
    jwt,
    did,
    jwk,
    hexPrivateKey,
    hexPublicKey,
  } = mockedGetEnterpriseAuthToken(inputToken.enterpiseName);
  const state = DidAuthUtil.getState();
  const didAuthResponsePayload: DidAuthTypes.DidAuthResponsePayload = {
    iss: DidAuthTypes.DidAuthResponseIss.SELF_ISSUE,
    sub: getThumbprint(hexPrivateKey),
    nonce: inputToken.nonce || DidAuthUtil.getNonce(state),
    aud: "https://app.example/demo",
    sub_jwk: getPublicJWKFromPrivateHex(hexPrivateKey, `${did}#keys-1`),
    did,
  };

  const header: JWTHeader = {
    alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256K,
    typ: "JWT",
    kid: `${did}#keys-1`,
  };

  const idToken = JWT.sign(didAuthResponsePayload, jwk, {
    header,
    issuer: didAuthResponsePayload.iss,
    kid: false,
  });

  return {
    jwt,
    did,
    jwk,
    idToken,
    hexPublicKey,
    header,
    payload: didAuthResponsePayload,
  };
};

export interface DidKey {
  did: string;
  publicKeyHex?: string;
  jwk?: JWKECKey;
}

export const getParsedDidDocument = (didKey: DidKey): DIDDocument => {
  if (didKey.publicKeyHex) {
    const didDocB58 = DID_DOCUMENT_PUBKEY_B58;
    didDocB58.id = didKey.did;
    didDocB58.controller = didKey.did;
    didDocB58.authentication[0].publicKey = `${didKey.did}#keys-1`;
    didDocB58.verificationMethod[0].id = `${didKey.did}#keys-1`;
    didDocB58.verificationMethod[0].controller = didKey.did;
    didDocB58.verificationMethod[0].publicKeyBase58 = base58.encode(
      Buffer.from(didKey.publicKeyHex.replace("0x", ""), "hex")
    );
    return didDocB58;
  }
  // then didKey jws public key
  const didDocJwk = DID_DOCUMENT_PUBKEY_JWK;
  didDocJwk.id = didKey.did;
  didDocJwk.controller = didKey.did;
  didDocJwk.authentication[0].publicKey = `${didKey.did}#keys-1`;
  didDocJwk.verificationMethod[0].id = `${didKey.did}#keys-1`;
  didDocJwk.verificationMethod[0].controller = didKey.did;
  didDocJwk.verificationMethod[0].publicKeyJwk = didKey.jwk as VidJWKECKey;
  return didDocJwk;
};
