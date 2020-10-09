import * as dotenv from "dotenv";

import {
  VidDidAuth,
  DidAuthRequestCall,
  DidAuthRequestPayload,
  DidAuthResponseCall,
  DIDAUTH_KEY_TYPE,
  getHexPrivateKey,
} from "../src/index";
import { TESTKEY, generateTestKey, getEnterpriseAuthZToken } from "./AuxTest";

// importing .env variables
dotenv.config();

jest.setTimeout(10000);

describe("test DID Auth End to end flow", () => {
  it("should test a whole DID-Auth flow using Enterprise wallet keys and User keys", async () => {
    expect.assertions(8);
    const WALLET_API_BASE_URL =
      process.env.WALLET_API_URL || "http://localhost:9000";
    const RPC_PROVIDER = process.env.DID_PROVIDER_RPC_URL || "https://api.intebsi.xyz/ledger/v1/blockchains/besu";
    const RPC_ADDRESS = process.env.DID_REGISTRY_SC_ADDRESS || "0x00000000";
    const testKeyUser: TESTKEY = generateTestKey(DIDAUTH_KEY_TYPE.EC);
    const entityAA = await getEnterpriseAuthZToken("COMPANY E2E INC");
    const tokenEntity = entityAA.jwt;
    // CREATE A DID-AUTH REQUEST URI
    const didAuthRequestCall: DidAuthRequestCall = {
      redirectUri: "http://localhost:8080/demo/spanish-university",
      signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
      authZToken: tokenEntity,
    };
    // Create URI using the wallet backend that manages entity DID keys
    const { uri, nonce } = await VidDidAuth.createUriRequest(
      didAuthRequestCall
    );
    // Parsing URI parameters to get the Request Object and Redirect URI as client_id
    const params = new URLSearchParams(uri);
    const redirectUri = params.get("client_id");
    const didAuthRequestJwt = params.get("request");
    expect(redirectUri).toMatch(didAuthRequestCall.redirectUri);
    expect(didAuthRequestJwt).toBeDefined();
    expect(nonce).toBeDefined();
    // VERIFY DID-AUTH REQUEST
    const requestPayload: DidAuthRequestPayload = await VidDidAuth.verifyDidAuthRequest(
      didAuthRequestJwt as string,
      RPC_ADDRESS,
      RPC_PROVIDER
    );
    expect(requestPayload).toBeDefined();
    // CREATE A DID-AUTH RESPONSE
    const didAuthResponseCall: DidAuthResponseCall = {
      hexPrivatekey: getHexPrivateKey(testKeyUser.key),
      did: testKeyUser.did,
      nonce,
      redirectUri: redirectUri as string,
    };
    const didAuthResponseJwt = await VidDidAuth.createDidAuthResponse(
      didAuthResponseCall
    );
    expect(didAuthResponseJwt).toBeDefined();
    const response = await VidDidAuth.verifyDidAuthResponse(
      didAuthResponseJwt,
      `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
      tokenEntity,
      requestPayload.nonce
    );
    expect(response).toBeDefined();
    expect(response).toHaveProperty("signatureValidation");
    expect(response.signatureValidation).toBe(true);
  });
});
