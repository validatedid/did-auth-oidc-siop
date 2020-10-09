import { JWT, JWK } from "jose";
import { DIDDocument } from "did-resolver";
import { ethers } from "ethers";
import { v4 as uuidv4 } from "uuid";
import { decodeJWT } from "did-jwt";
import axios from "axios";
import {
  DIDAUTH_ERRORS,
  JWTClaims,
  getDIDFromKey,
  DIDAUTH_KEY_TYPE,
  DIDAUTH_KEY_CURVE,
} from "../src";

import moment = require("moment");

export const DIDAUTH_HEADER = {
  typ: "JWT",
  alg: "ES256K-R",
  kid: "did:ebsi:0x416e6e6162656c2e4c65652e452d412d506f652e#key1",
};

export const DIDAUTH_REQUEST_PAYLOAD = {
  iss: "did:ebsi:0x416e6e6162656c2e4c65652e452d412d506f652e", // DID of the RP (kid must point to a key in this DID Document)
  scope: "openid did_authn", // MUST be "openid did_authn"
  response_type: "id_token", // MUST be ID Token
  client_id: "redirect-uri", // Redirect URI after successful authentication
  nonce: "n-0S6_WzA2M", // MUST be a random string from a high-entropy source
  exp: 1569937756, // Unix Timestamp; Date and time when the ID Token expires.
  iat: 1569934156,
};

export const DIDAUTH_RESPONSE_PAYLOAD = {
  iss: "https://self-issued.me",
  sub: "QS+5mH5GqVxuah94+D9wV97mMKZ6iMzW1op4B4s02Jk=", // Thumbprint of the sub_jwk
  aud: "redirect-uri", // MUST be client_id from the Request Object
  exp: 1569937756, // Unix Timestamp; Date and time when the ID Token expires.
  iat: 1569934156, // Unix Timestamp; Date and time when the Token was issued.
  nonce: "6a6b57a9d4e1a130b0edbe1ec4ae8823",
  sub_jwk: {
    crv: "secp256k1",
    kid: "did:ebsi:0x226e2e2223333c2e4c65652e452d412d50611111#key-1",
    kty: "EC",
    x: "7KEKZa5xJPh7WVqHJyUpb2MgEe3nA8Rk7eUlXsmBl-M",
    y: "3zIgl_ml4RhapyEm5J7lvU-4f5jiBvZr4KgxUjEhl9o",
  },
};

export interface TESTKEY {
  key: JWK.ECKey;
  did: string;
  didDoc?: DIDDocument;
}

export function generateTestKey(kty: string): TESTKEY {
  let key: JWK.ECKey;

  switch (kty) {
    case DIDAUTH_KEY_TYPE.EC:
      key = JWK.generateSync(DIDAUTH_KEY_TYPE.EC, DIDAUTH_KEY_CURVE.SECP256k1, {
        use: "sig",
      });
      break;
    default:
      throw new Error(DIDAUTH_ERRORS.NO_ALG_SUPPORTED);
  }

  const did = getDIDFromKey(key);

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
  iss: string;
  aud: string;
  nonce: string;
}

const testEntityAuthNToken = async (
  enterpiseName?: string
): Promise<{ jwt: string; jwk: JWK.ECKey; did: string }> => {
  // generate a new keypair
  const jwk = JWK.generateSync("EC", "secp256k1", { use: "sig" });
  const privKeyString = Buffer.from(jwk.d as string, "base64").toString("hex");
  const wallet: ethers.Wallet = new ethers.Wallet(privKeyString);
  const did = `did:ebsi:${wallet.address}`;

  const payload: LegalEntityAuthNToken = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "ebsi-wallet",
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

export function getEnterpriseDID(token: string): string {
  const { payload } = JWT.decode(token, { complete: true });

  return (payload as IEnterpriseAuthZToken).did;
}

async function doPostCall(url: string, data: any): Promise<any> {
  const response = await axios.post(url, data);
  return response;
}

export async function getEnterpriseAuthZToken(
  enterpiseName?: string
): Promise<{
  jwt: string;
  did: string;
}> {
  const testAuth = await testEntityAuthNToken(enterpiseName);
  const payload = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: testAuth.jwt,
    scope: "ebsi profile entity",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "http://localhost:9000";
  // Create and sign JWT
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/wallet/v1/sessions`,
    payload
  );

  return {
    jwt: result.data.accessToken,
    did: getEnterpriseDID(result.data.accessToken),
  };
}

export async function mockedGetEnterpriseAuthToken(
  enterpiseName?: string
): Promise<{
  jwt: string;
  did: string;
  jwk: JWK.ECKey;
}> {
  const testAuth = await testEntityAuthNToken(enterpiseName);
  const { payload } = decodeJWT(testAuth.jwt);

  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,
    aud: payload?.iss ? payload.iss : "Test Legal Entity",
    nonce: payload.nonce,
  };

  const ebsiPayload = {
    ...inputPayload,
    ...{
      sub: payload.iss, // Should be the id of the app that is requesting the token
      iat: moment().unix(),
      exp: moment().add(15, "minutes").unix(),
      aud: "ebsi-wallet",
    },
  };

  const jwt = JWT.sign(ebsiPayload, testAuth.jwk, {
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
