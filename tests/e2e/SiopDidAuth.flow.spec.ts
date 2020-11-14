import { parse } from "querystring";
import * as dotenv from "dotenv";
import * as siopDidAuth from "../../src";
import {
  DidAuthTypes,
  DidAuthUtil,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
} from "../../src";
import { getEnterpriseAuthZToken, mockedKeyAndDid } from "../AuxTest";
import {
  DidAuthResponseMode,
  DidAuthVerifyOpts,
} from "../../src/interfaces/DIDAuth.types";

// importing .env variables
dotenv.config();

describe("SIOP DID Auth end to end flow tests should", () => {
  it("create a request externally, verify it internally, create a response internally and verify it externally", async () => {
    expect.assertions(12);
    const WALLET_API_BASE_URL = process.env.WALLET_API_URL;
    const entityAA = await getEnterpriseAuthZToken("COMPANY E2E INC");
    const authZToken = entityAA.jwt;
    const entityDid = entityAA.did;

    // create request internally
    const requestOpts: DidAuthTypes.DidAuthRequestOpts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: "https://dev.vidchain.net/siop/jwts",
      },
      signatureType: {
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        did: entityDid,
        authZToken,
        kid: `${entityDid}#key-1`,
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${entityDid};transform-keys=jwks`,
      },
    };

    const uriRequest = await siopDidAuth.createUriRequest(requestOpts);
    expect(uriRequest).toBeDefined();
    expect(uriRequest).toHaveProperty("jwt");
    expect(uriRequest.jwt).toBeDefined();

    // verify request internally
    const optsVerifyRequest: DidAuthVerifyOpts = {
      verificationType: {
        registry: process.env.DID_REGISTRY_SC_ADDRESS,
        rpcUrl: process.env.DID_PROVIDER_RPC_URL,
      },
    };
    const validationRequestResponse = await verifyDidAuthRequest(
      uriRequest.jwt,
      optsVerifyRequest
    );
    expect(validationRequestResponse).toBeDefined();
    expect(validationRequestResponse.signatureValidation).toBe(true);
    expect(validationRequestResponse.payload).toBeDefined();

    // create a response internally
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const nonce = DidAuthUtil.getNonce(state);
    const responseOpts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://app.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
      },
      nonce,
      state,
      responseMode: DidAuthResponseMode.FORM_POST,
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
    };
    const uriResponse = await siopDidAuth.createUriResponse(responseOpts);
    expect(uriResponse).toBeDefined();
    expect(uriResponse).toHaveProperty("bodyEncoded");
    const urlDecoded = decodeURIComponent(uriResponse.bodyEncoded);
    const data = parse(urlDecoded);
    expect(data.id_token).toBeDefined();

    // verify a response externally
    const optsVerifyResponse: DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken,
      },
      nonce,
    };
    const validationResponse = await verifyDidAuthResponse(
      data.id_token as string,
      optsVerifyResponse
    );
    expect(validationResponse).toBeDefined();
    expect(validationResponse.signatureValidation).toBe(true);
    expect(validationResponse.payload).toBeDefined();
  });
});
