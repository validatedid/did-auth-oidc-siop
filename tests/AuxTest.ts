import { JWT, JWK } from "jose";
import { DIDDocument } from "did-resolver";
import { v4 as uuidv4 } from "uuid";
import { decodeJWT } from "did-jwt";
import axios, { AxiosResponse } from "axios";
import moment from "moment";
import { ethers } from "ethers";

import { DidAuthErrors, JWTClaims, DidAuthUtil } from "../src";
import { prefixWith0x } from "../src/util/Util";
import {
  DidAuthKeyCurve,
  DidAuthKeyType,
} from "../src/interfaces/DIDAuth.types";

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
} => {
  // generate a new keypair
  const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
  const hexPrivateKey = Buffer.from(jwk.d, "base64").toString("hex");
  const wallet: ethers.Wallet = new ethers.Wallet(prefixWith0x(hexPrivateKey));
  const did = `did:vid:${wallet.address}`;
  return { hexPrivateKey, did, jwk };
};

const mockedEntityAuthNToken = (
  enterpiseName?: string
): { jwt: string; jwk: JWK.ECKey; did: string } => {
  // generate a new keypair
  const { did, jwk } = mockedKeyAndDid();

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
  return { jwt, jwk, did };
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
  enterpiseName?: string
): {
  jwt: string;
  did: string;
  jwk: JWK.ECKey;
} {
  const testAuth = mockedEntityAuthNToken(enterpiseName);
  const { payload } = decodeJWT(testAuth.jwt);

  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,
    aud: payload?.iss ? payload.iss : "Test Legal Entity",
    nonce: (payload as IEnterpriseAuthZToken).nonce,
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
  };
}
