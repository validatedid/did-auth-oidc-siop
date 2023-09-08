import crypto from "crypto";
import {
  JWK,
  JWTPayload,
  importJWK,
  SignJWT,
  exportJWK,
  generateKeyPair,
} from "jose";
import { resolver as didKeyResolver } from "@transmute/did-key.js";
import { DIDResolutionResult, DIDDocument } from "did-resolver";
import { v4 as uuidv4 } from "uuid";
import axios, { AxiosResponse } from "axios";
import moment from "moment";
import { ethers } from "ethers";
import jwt_decode from "jwt-decode";
import base58 from "bs58";
import { Ed25519KeyPair, keyUtils } from "@transmute/did-key-ed25519";

import { decodeJWT, ES256KSigner, createJWT, EdDSASigner } from "did-jwt";

import { util } from "@cef-ebsi/key-did-resolver";
import { Buffer } from "buffer";
import { DidAuthErrors, JWTClaims, DidAuthUtil, DidAuthTypes } from "../src";
import { prefixWith0x } from "../src/util/Util";
import {
  DidAuthKeyAlgorithm,
  DidAuthKeyCurve,
  DidAuthKeyType,
} from "../src/interfaces/DIDAuth.types";
import { getPublicJWKFromPrivateHex, getThumbprint } from "../src/util/JWK";
import { EnterpriseAuthZToken, JWTHeader } from "../src/interfaces/JWT";
import {
  DID_DOCUMENT_PUBKEY_B58,
  DID_DOCUMENT_PUBKEY_JWK,
} from "./data/mockedData";

export interface TESTKEY {
  key: JWK;
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

const toHex = (data: string): string =>
  Buffer.from(data, "base64").toString("hex");
const getPublicKeyHexFromJWK = (jwk: JWK): string => {
  const publikKeyHex = `0x04${toHex(jwk.x)}${toHex(jwk.y)}`;
  return publikKeyHex;
};

export async function generateTestKey(kty: string): Promise<TESTKEY> {
  if (kty !== DidAuthKeyType.EC)
    throw new Error(DidAuthErrors.NO_ALG_SUPPORTED);
  const key = crypto.generateKeyPairSync("ec", {
    namedCurve: DidAuthKeyCurve.SECP256k1,
  });
  const privateJwk = await exportJWK(key.privateKey);

  const did = DidAuthUtil.getDIDFromKey(privateJwk);

  return {
    key: privateJwk,
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

export interface UserTestAuthNToken extends JWTClaims {
  iss: string; // DID of the User
  aud: string; // RP Application Name. usually vidchain-wallet
  publicKey: string; // MUST be user's public key from which the `iss` DID is derived.
}

export interface UserAuthZToken extends JWTClaims {
  sub: string;
  iat?: number; // The date at a time when the Access Token was issued.
  exp?: number; // The date and time on or after which the token MUST NOT be accepted for processing. (expiry is 900s)
  aud?: string; // Name of the application,  as registered in the Trusted Apps Registry, to which the Access Token is intended for.
  did: string; // DID of the user as specified in the Access Token Request.
}

export const mockedKeyAndDid = async (): Promise<{
  hexPrivateKey: string;
  did: string;
  jwk: JWK;
  hexPublicKey: string;
}> => {
  // generate a new keypair
  const key = crypto.generateKeyPairSync("ec", {
    namedCurve: DidAuthKeyCurve.SECP256k1,
  });
  const privateJwk = await exportJWK(key.privateKey);
  const hexPrivateKey = Buffer.from(privateJwk.d, "base64").toString("hex");
  const wallet: ethers.Wallet = new ethers.Wallet(prefixWith0x(hexPrivateKey));
  const did = `did:ethr:${wallet.address}`;
  const hexPublicKey = wallet.publicKey;

  return {
    hexPrivateKey,
    did,
    jwk: privateJwk,
    hexPublicKey,
  };
};

interface KeyPair {
  id: string;
  type: string;
  controller: string;
  publicKeyBase58: string;
  privateKeyBase58: string;
}

export const mockedKeyAndDidKey = async (
  seed?: string
): Promise<{
  hexPrivateKey: string;
  did: string;
  hexPublicKey: string;
  kid: string;
  privateKeyBuffer: Buffer;
}> => {
  const key = await Ed25519KeyPair.generate({
    secureRandom: () => {
      return seed ? Buffer.from(seed, "hex") : crypto.randomBytes(32);
    },
  });
  const keyPair = key.toKeyPair(true) as KeyPair;
  const hexPublicKey = keyUtils.publicKeyHexFromPublicKeyBase58(
    keyPair.publicKeyBase58
  ) as string;
  const hexPrivateKey = keyUtils.privateKeyHexFromPrivateKeyBase58(
    keyPair.privateKeyBase58
  ) as string;
  const publicKeyJwk = keyUtils.publicKeyJwkFromPublicKeyBase58(
    keyPair.publicKeyBase58
  ) as JWK;
  const { kid } = publicKeyJwk;

  return {
    hexPrivateKey,
    did: key.controller,
    hexPublicKey,
    kid,
    privateKeyBuffer: key.privateKeyBuffer,
  };
};

export const mockedKeyAndDidKeyES256 = async (
  seed?: string
): Promise<{
  hexPrivateKey: string;
  did: string;
  hexPublicKey: string;
  kid: string;
  jwkPrivateKey: JWK;
}> => {
  const keypair = await generateKeyPair(DidAuthKeyAlgorithm.ES256, {
    crv: "EC",
  });

  const jwkPublicKey = await exportJWK(keypair.publicKey);
  const jwkPrivateKey = await exportJWK(keypair.privateKey);
  const did = util.createDid(jwkPublicKey);

  const hexPublicKey = getPublicKeyHexFromJWK(jwkPublicKey);
  const hexPrivateKey = toHex(jwkPrivateKey.d);

  return {
    hexPrivateKey,
    did,
    hexPublicKey,
    kid: `${did}#${did.split(":")[2]}`,
    jwkPrivateKey,
  };
};

export const getUserTestAuthNToken = async (): Promise<{
  hexPrivateKey: string;
  did: string;
  jwk: JWK;
  hexPublicKey: string;
  assertion: string;
}> => {
  const { hexPrivateKey, did, jwk, hexPublicKey } = await mockedKeyAndDid();
  const payload: UserTestAuthNToken = {
    iss: did,
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "seconds").unix(),
    publicKey: hexPublicKey,
  };
  const signer = ES256KSigner(hexPrivateKey.replace("0x", ""), true); // Removing 0x from wallet private key as input of ES256KSigner
  const assertionToken = await createJWT(payload, {
    issuer: did,
    alg: "ES256K-R",
    signer,
  });
  return {
    hexPrivateKey,
    did,
    jwk,
    hexPublicKey,
    assertion: assertionToken,
  };
};

export const getUserTestAuthNTokenDidKey = async (): Promise<{
  hexPrivateKey: string;
  did: string;
  hexPublicKey: string;
  assertion: string;
  kid: string;
}> => {
  const { hexPrivateKey, did, hexPublicKey, kid, privateKeyBuffer } =
    await mockedKeyAndDidKey();
  const payload: UserTestAuthNToken = {
    iss: did,
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "seconds").unix(),
    publicKey: hexPublicKey,
  };
  const signer = EdDSASigner(Buffer.from(privateKeyBuffer).toString("base64"));
  const assertionToken = await createJWT(payload, {
    issuer: did,
    alg: "EdDSA",
    signer,
  });
  return {
    hexPrivateKey,
    did,
    hexPublicKey,
    assertion: assertionToken,
    kid,
  };
};

export const getUserTestAuthNTokenDidKeyES256 = async (): Promise<{
  hexPrivateKey: string;
  did: string;
  hexPublicKey: string;
  assertion: string;
  kid: string;
}> => {
  const { hexPrivateKey, did, hexPublicKey, kid, jwkPrivateKey } =
    await mockedKeyAndDidKeyES256();
  const payload: UserTestAuthNToken = {
    iss: did,
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "seconds").unix(),
    publicKey: hexPublicKey,
  };

  const header: {
    typ: "JWT";
    alg: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [x: string]: any;
  } = {
    alg: DidAuthKeyAlgorithm.ES256,
    typ: "JWT",
  };
  const data = Buffer.from(JSON.stringify(payload));
  const jws = await new SignJWT(JSON.parse(data.toString()) as JWTPayload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .setIssuer(did)
    .sign(await importJWK(jwkPrivateKey, header.alg));

  return {
    hexPrivateKey,
    did,
    hexPublicKey,
    assertion: jws,
    kid,
  };
};

const mockedEntityAuthNToken = async (
  enterpiseName?: string
): Promise<{
  jwt: string;
  jwk: JWK;
  did: string;
  hexPrivateKey: string;
  hexPublicKey: string;
}> => {
  // generate a new keypair
  const { did, jwk, hexPrivateKey, hexPublicKey } = await mockedKeyAndDid();

  const payload: LegalEntityTestAuthN = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "minutes").unix(),
    nonce: uuidv4(),
  };

  const privateKey = await importJWK(
    jwk,
    DidAuthTypes.DidAuthKeyAlgorithm.ES256K
  );
  const jwt = await new SignJWT(payload as unknown as JWTPayload)
    .setProtectedHeader({
      alg: "ES256K",
      typ: "JWT",
    })
    .sign(privateKey);
  return { jwt, jwk, did, hexPrivateKey, hexPublicKey };
};

const testEntityAuthNToken = (enterpiseName?: string): { jwt: string } => {
  const { ENTITY_TEST_API_KEY } = process.env;
  const payload: LegalEntityAuthNToken = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "minutes").unix(),
    nonce: uuidv4(),
    apiKey: ENTITY_TEST_API_KEY,
  };

  const jwt = Buffer.from(JSON.stringify(payload)).toString("base64");
  return { jwt };
};

export function getEnterpriseDID(token: string): string {
  const payload = jwt_decode(token);

  return (payload as EnterpriseAuthZToken).did;
}

async function doPostCall(url: string, data: unknown): Promise<AxiosResponse> {
  const response = await axios.post(url, data);
  return response;
}

interface ApiKeyStruct {
  type: string;
  authenticationKey: string;
}

const getEntityAuthNToken = (enterpiseName?: string): { jwt: string } => {
  const { ENTITY_TEST_API_KEY } = process.env;

  const payload: LegalEntityAuthNToken = {
    iss: enterpiseName || "Test Legal Entity",
    aud: "vidchain-api",
    iat: moment().unix(),
    exp: moment().add(15, "minutes").unix(),
    nonce: uuidv4(),
    apiKey: ENTITY_TEST_API_KEY,
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
  const auth = getEntityAuthNToken(enterpiseName);
  const payload = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: auth.jwt,
    scope: "vidchain profile entity",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "https://dev.vidchain.net";
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
    scope: "vidchain profile entity",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "https://dev.vidchain.net";
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

export async function getUserEntityTestAuthZToken(): Promise<{
  jwt: string;
  did: string;
  hexPrivateKey: string;
  jwk: JWK;
  hexPublicKey: string;
}> {
  const { hexPrivateKey, did, jwk, hexPublicKey, assertion } =
    await getUserTestAuthNToken();
  const payload = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
    scope: "vidchain profile user",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "https://dev.vidchain.net";
  // Create and sign JWT
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/api/v1/sessions`,
    payload
  );
  const { accessToken } = result.data as AccessTokenResponseBody;

  return {
    jwt: accessToken,
    did,
    hexPrivateKey,
    jwk,
    hexPublicKey,
  };
}

export async function getUserEntityTestAuthZTokenDidKey(): Promise<{
  jwt: string;
  did: string;
  hexPrivateKey: string;
  hexPublicKey: string;
  kid: string;
}> {
  const { hexPrivateKey, did, hexPublicKey, kid, assertion } =
    await getUserTestAuthNTokenDidKey();
  const payload = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
    scope: "vidchain profile user",
  };
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "https://dev.vidchain.net";
  // Create and sign JWT
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/api/v1/sessions`,
    payload
  );
  const { accessToken } = result.data as AccessTokenResponseBody;

  return {
    jwt: accessToken,
    did,
    hexPrivateKey,
    hexPublicKey,
    kid,
  };
}

export const getLegalEntityTestSessionTokenDidKey = async (): Promise<{
  jwt: string;
  did: string;
}> => {
  const { ENTITY_DID_KEY_TEST_API_KEY } = process.env;
  const legalEntity = {
    iss: "Did Key Test II",
    aud: "vidchain-api",
    nonce: crypto.randomBytes(16).toString("base64"),
    method: "key",
    apiKey: ENTITY_DID_KEY_TEST_API_KEY,
  };
  const sessionBody = {
    grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: Buffer.from(JSON.stringify(legalEntity)).toString("base64"),
    scope: "vidchain profile entity",
  };

  // Sessions
  const WALLET_API_BASE_URL =
    process.env.WALLET_API_URL || "https://dev.vidchain.net";
  // Create and sign JWT
  const result = await doPostCall(
    `${WALLET_API_BASE_URL}/api/v1/sessions`,
    sessionBody
  );
  const { accessToken } = result.data as AccessTokenResponseBody;
  const { payload } = decodeJWT(accessToken);

  return {
    jwt: accessToken,
    did: (payload as unknown as IEnterpriseAuthZToken).did,
  };
};

export async function mockedGetEnterpriseAuthToken(
  enterpriseName?: string
): Promise<{
  jwt: string;
  did: string;
  jwk: JWK;
  hexPrivateKey: string;
  hexPublicKey: string;
}> {
  const testAuth = await mockedEntityAuthNToken(enterpriseName);
  const payload = jwt_decode(testAuth.jwt);

  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    aud: (payload as JWTClaims)?.iss
      ? (payload as JWTClaims).iss
      : "Test Legal Entity",
    nonce: (payload as IEnterpriseAuthZToken).nonce,
  };

  const vidPayload = {
    ...inputPayload,
    ...{
      sub: (payload as JWTClaims).iss, // Should be the id of the app that is requesting the token
      iat: moment().unix(),
      exp: moment().add(15, "minutes").unix(),
      aud: "vidchain-api",
    },
  };

  const privateKey = await importJWK(
    testAuth.jwk,
    DidAuthTypes.DidAuthKeyAlgorithm.ES256K
  );
  const jwt = await new SignJWT(vidPayload)
    .setProtectedHeader({
      alg: "ES256K",
      typ: "JWT",
    })
    .sign(privateKey);

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

export const mockedIdToken = async (
  inputToken: InputToken
): Promise<{
  jwt: string;
  did: string;
  jwk: JWK;
  idToken: string;
  hexPublicKey: string;
  header: JWTHeader;
  payload: DidAuthTypes.DidAuthResponsePayload;
}> => {
  const { jwt, did, jwk, hexPrivateKey, hexPublicKey } =
    await mockedGetEnterpriseAuthToken(inputToken.enterpiseName);
  const state = DidAuthUtil.getState();
  const didAuthResponsePayload: DidAuthTypes.DidAuthResponsePayload = {
    iss: DidAuthTypes.DidAuthResponseIss.SELF_ISSUE,
    sub: getThumbprint(hexPrivateKey, did),
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

  const privateKey = await importJWK(
    jwk,
    DidAuthTypes.DidAuthKeyAlgorithm.ES256K
  );
  const idToken = await new SignJWT(didAuthResponsePayload)
    .setProtectedHeader({
      alg: "ES256K",
      typ: "JWT",
    })
    .setIssuer(didAuthResponsePayload.iss)
    .sign(privateKey);

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
  jwk?: JWK;
}

interface FixJwk extends JWK {
  kty: string;
}

export const getParsedDidDocument = (didKey: DidKey): DIDDocument => {
  if (didKey.publicKeyHex) {
    const didDocB58 = DID_DOCUMENT_PUBKEY_B58;
    didDocB58.id = didKey.did;
    didDocB58.controller = didKey.did;
    didDocB58.verificationMethod[0].id = `${didKey.did}#keys-1`;
    didDocB58.verificationMethod[0].controller = didKey.did;
    didDocB58.verificationMethod[0].publicKeyBase58 = base58.encode(
      Buffer.from(didKey.publicKeyHex.replace("0x", ""), "hex")
    );
    return didDocB58;
  }
  // then didKey jws public key
  const didDocJwk = DID_DOCUMENT_PUBKEY_JWK;
  const { jwk } = didKey;
  jwk.kty = didKey.jwk.kty || "EC";
  didDocJwk.id = didKey.did;
  didDocJwk.controller = didKey.did;
  didDocJwk.verificationMethod[0].id = `${didKey.did}#keys-1`;
  didDocJwk.verificationMethod[0].controller = didKey.did;
  didDocJwk.verificationMethod[0].publicKeyJwk = jwk as FixJwk;
  return didDocJwk;
};

export const getPublicJWKFromDid = async (did: string): Promise<JWK> => {
  const API_BASE_URL = process.env.WALLET_API_URL || "https://dev.vidchain.net";
  const response = await axios.get(
    `${API_BASE_URL}/api/v1/identifiers/${did};transform-keys=jwks`
  );

  return (response.data as DIDDocument).verificationMethod[0].publicKeyJwk;
};

export const resolveDidKey = async (
  did: string
): Promise<DIDResolutionResult> => {
  return (await didKeyResolver.resolve(did)) as DIDResolutionResult;
};

export const getKidFromDID = async (did: string) => {
  const { didDocument } = await resolveDidKey(did);
  const inputVerificationMethod = didDocument.verificationMethod;
  const publicKeyJwk = keyUtils.publicKeyJwkFromPublicKeyBase58(
    inputVerificationMethod[0].publicKeyBase58
  ) as JWK;
  return publicKeyJwk.kid;
};

export const getKidFromDIDES256 = (did: string) => {
  return `${did}#${did.split(":")[2]}`;
};
