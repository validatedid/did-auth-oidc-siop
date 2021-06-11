import { parse } from "querystring";
import * as dotenv from "dotenv";
import { decodeJWT } from "did-jwt";
import * as siopDidAuth from "../../src";
import {
  DidAuthTypes,
  DidAuthUtil,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
} from "../../src";
import {
  getLegalEntityAuthZToken,
  getLegalEntityTestAuthZToken,
  getUserEntityTestAuthZToken,
} from "../AuxTest";
import {
  DidAuthResponseMode,
  DidAuthVerifyOpts,
} from "../../src/interfaces/DIDAuth.types";
import * as mockedData from "../data/mockedData";

// importing .env variables
dotenv.config();

jest.setTimeout(30000);

describe("SIOP DID Auth end to end flow tests should", () => {
  it("create a request externally, verify it internally, create a response internally and verify it externally", async () => {
    expect.assertions(12);
    const WALLET_API_BASE_URL = process.env.WALLET_API_URL;
    const entityAA = await getLegalEntityTestAuthZToken("COMPANY E2E INC");
    const authZToken = entityAA.jwt;
    const entityDid = entityAA.did;

    // create request internally
    const requestOpts: DidAuthTypes.DidAuthRequestOpts = {
      redirectUri: "https://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: `${WALLET_API_BASE_URL}/siop/jwts`,
      },
      signatureType: {
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        did: entityDid,
        authZToken,
        kid: `${entityDid}#keys-1`,
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: `${WALLET_API_BASE_URL}/api/v1/identifiers/${entityDid};transform-keys=jwks`,
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
        didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
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
    const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
    const state = DidAuthUtil.getState();
    const nonce = DidAuthUtil.getNonce(state);
    const responseOpts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://app.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
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
    const urlDecoded = decodeURI(uriResponse.bodyEncoded);
    const data = parse(urlDecoded);
    expect(data.id_token).toBeDefined();

    // verify a response externally
    const optsVerifyResponse: DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken,
        didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
      },
      nonce,
      redirectUri: requestOpts.redirectUri,
    };
    const validationResponse = await verifyDidAuthResponse(
      data.id_token as string,
      optsVerifyResponse
    );
    expect(validationResponse).toBeDefined();
    expect(validationResponse.signatureValidation).toBe(true);
    expect(validationResponse.payload).toBeDefined();
  });

  it("create an app 2 app flow", async () => {
    expect.assertions(10);
    const WALLET_API_BASE_URL = process.env.WALLET_API_URL;
    const entityAA = await getLegalEntityAuthZToken("ODYSSEY APP TEST");
    const authZToken = entityAA.jwt;
    const entityDid = entityAA.did;
    const state = DidAuthUtil.getState();

    // create request externally passing the request via value (in the Url)
    const requestOpts: DidAuthTypes.DidAuthRequestOpts = {
      oidpUri: "vidchain://did-auth",
      redirectUri: "odysseyapp://example/did-auth",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      signatureType: {
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        did: entityDid,
        authZToken,
        kid: `${entityDid}#keys-1`,
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: `${WALLET_API_BASE_URL}/api/v1/identifiers/${entityDid};transform-keys=jwks`,
      },
      responseMode: DidAuthTypes.DidAuthResponseMode.FRAGMENT,
      responseContext: DidAuthTypes.DidAuthResponseContext.RP,
      state,
      claims: mockedData.verifiableIdOidcClaim,
    };

    const uriRequest = await siopDidAuth.createUriRequest(requestOpts);
    expect(uriRequest).toBeDefined();
    expect(uriRequest).toHaveProperty("urlEncoded");
    const uriDecoded = decodeURI(uriRequest.urlEncoded);
    expect(uriDecoded).toContain(`openid://`);
    expect(uriDecoded).toContain(
      `?response_type=${DidAuthTypes.DidAuthResponseType.ID_TOKEN}`
    );
    const data = parse(uriDecoded);
    expect(data.request).toBeDefined();
    const authRequestToken = data.request as string;

    // verify request internally
    const optsVerifyRequest: DidAuthVerifyOpts = {
      verificationType: {
        registry: process.env.DID_REGISTRY_SC_ADDRESS,
        rpcUrl: process.env.DID_PROVIDER_RPC_URL,
        didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
      },
    };
    const validationRequestResponse = await siopDidAuth.verifyDidAuthRequest(
      authRequestToken,
      optsVerifyRequest
    );
    expect(validationRequestResponse).toBeDefined();
    expect(validationRequestResponse.payload).toBeDefined();

    const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
    const requestPayload = validationRequestResponse.payload as DidAuthTypes.DidAuthRequestPayload;
    const stateRequest = requestPayload.state;
    const nonceRequest = requestPayload.nonce;

    const responseOpts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: requestPayload.client_id,
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      nonce: nonceRequest,
      state: stateRequest,
      responseMode: DidAuthResponseMode.FRAGMENT,
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
      vp: mockedData.verifiableIdPresentation,
    };

    const uriResponse = await siopDidAuth.createUriResponse(responseOpts);
    expect(uriResponse).toBeDefined();
    const uriResponseDecoded = decodeURI(uriResponse.urlEncoded);
    const splitUrl = uriResponseDecoded.split("#");
    const responseData = parse(splitUrl[1]);
    expect(responseData.id_token).toBeDefined();
    const authResponseToken = responseData.id_token as string;
    const { payload } = decodeJWT(authResponseToken);

    const optsVerify: DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken,
        didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
      },
      nonce: (payload as DidAuthTypes.DidAuthResponsePayload).nonce,
      redirectUri: requestPayload.client_id,
    };
    const validationResponse = await verifyDidAuthResponse(
      authResponseToken,
      optsVerify
    );
    expect(validationResponse).toBeDefined();
  });
});
