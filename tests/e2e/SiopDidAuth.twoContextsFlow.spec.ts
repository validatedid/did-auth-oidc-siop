import { parse } from "querystring";
import * as dotenv from "dotenv";
import { decodeJwt } from "@validatedid/did-jwt";
import * as siopDidAuth from "../../src";
import {
  DidAuthTypes,
  DidAuthUtil,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
} from "../../src";
import {
  getLegalEntityAuthZToken,
  getUserEntityTestAuthZToken,
} from "../AuxTest";
import { DidAuthVerifyOpts } from "../../src/interfaces/DIDAuth.types";
import * as mockedData from "../data/mockedData";

// importing .env variables
dotenv.config();

describe("SIOP DID Auth end to end flow tests should", () => {
  it("create a desktop web request to an app flow", async () => {
    expect.assertions(32);
    const WALLET_API_BASE_URL = process.env.WALLET_API_URL;
    const entity007 = await getLegalEntityAuthZToken("LEGAL ENTITY TEST 007");
    const authZToken = entity007.jwt;
    const entityDid = entity007.did;
    const state = DidAuthUtil.getState();

    // create request externally passing the request via refernce
    const requestOpts: DidAuthTypes.DidAuthRequestOpts = {
      redirectUri: "https://entity.example/did-auth",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: "https://entity.example/siop/jwts",
      },
      signatureType: {
        signatureUri: `${WALLET_API_BASE_URL}/api/v1/signatures`,
        did: entityDid,
        authZToken,
        kid: `${entityDid}#keys-1`,
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: `https://dev.vidchain.net/api/v1/identifiers/${entityDid};transform-keys=jwks`,
      },
      responseMode: DidAuthTypes.DidAuthResponseMode.FORM_POST,
      responseContext: DidAuthTypes.DidAuthResponseContext.WALLET,
      state,
      claims: mockedData.verifiableIdOidcClaim,
    };

    const uriRequest = await siopDidAuth.createUriRequest(requestOpts);
    expect(uriRequest).toBeDefined();
    expect(uriRequest).toHaveProperty("urlEncoded");
    expect(uriRequest).toHaveProperty("encoding");
    const uriDecoded = decodeURI(uriRequest.urlEncoded);
    expect(uriDecoded).toContain(`openid://`);
    expect(uriDecoded).toContain(
      `?response_type=${DidAuthTypes.DidAuthResponseType.ID_TOKEN}`
    );
    expect(uriDecoded).toContain(`&client_id=${requestOpts.redirectUri}`);
    expect(uriDecoded).toContain(
      `&scope=${DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN}`
    );
    expect(uriDecoded).toContain(`&requestUri=`);
    const data = parse(uriDecoded);
    expect(data.requestUri).toStrictEqual(
      requestOpts.requestObjectBy.referenceUri
    );
    expect(uriRequest).toHaveProperty("jwt");
    expect(uriRequest.jwt).toBeDefined();
    const decodedPayload = decodeJwt(uriRequest.jwt);
    const requestPayload = decodedPayload.payload as DidAuthTypes.DidAuthRequestPayload;
    expect(requestPayload.response_mode).toBe(
      DidAuthTypes.DidAuthResponseMode.FORM_POST
    );
    expect(requestPayload.response_context).toBe(
      DidAuthTypes.DidAuthResponseContext.WALLET
    );
    // VERIFY DID AUTH REQUEST
    const optsRequestVerify: DidAuthTypes.DidAuthVerifyOpts = {
      verificationType: {
        registry: process.env.DID_REGISTRY_SC_ADDRESS,
        rpcUrl: process.env.DID_PROVIDER_RPC_URL,
        didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
      },
    };
    const validationRequestResponse = await verifyDidAuthRequest(
      uriRequest.jwt,
      optsRequestVerify
    );
    expect(validationRequestResponse).toBeDefined();
    expect(validationRequestResponse.signatureValidation).toBe(true);
    expect(validationRequestResponse.payload).toBeDefined();

    const expectedPayload = mockedData.DIDAUTH_REQUEST_PAYLOAD;
    expectedPayload.iss = entityDid;
    expectedPayload.nonce = requestPayload.nonce;
    expectedPayload.state = state;
    expectedPayload.client_id = requestOpts.redirectUri;
    expectedPayload.iat = expect.any(Number) as number;
    expectedPayload.exp = expect.any(Number) as number;
    expectedPayload.registration = {
      jwks_uri: `https://dev.vidchain.net/api/v1/identifiers/${entityDid};transform-keys=jwks`,
      id_token_signed_response_alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256K,
    };

    expect(validationRequestResponse.payload.iat).toBeDefined();
    expect(validationRequestResponse.payload).toMatchObject(expectedPayload);
    expect(validationRequestResponse.payload.exp).toStrictEqual(
      validationRequestResponse.payload.iat + 5 * 60
    ); // 5 minutes of expiration time

    // CREATE URI RESPONSE
    const { hexPrivateKey, did } = await getUserEntityTestAuthZToken();
    const responseOpts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: requestPayload.client_id,
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      nonce: requestPayload.nonce,
      state: requestPayload.state,
      responseMode: requestPayload.response_mode,
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
      vp: mockedData.verifiableIdPresentation,
    };

    const uriResponse = await siopDidAuth.createUriResponse(responseOpts);
    expect(uriResponse).toBeDefined();
    expect(uriResponse).toHaveProperty("urlEncoded");
    expect(uriResponse).toHaveProperty("encoding");
    expect(uriResponse).toHaveProperty("response_mode");
    expect(uriResponse).toHaveProperty("bodyEncoded");
    expect(uriResponse.encoding).toStrictEqual(
      DidAuthTypes.UrlEncodingFormat.FORM_URL_ENCODED
    );
    expect(uriResponse.response_mode).toStrictEqual(
      DidAuthTypes.DidAuthResponseMode.FORM_POST
    );
    expect(decodeURI(uriResponse.urlEncoded)).toContain(
      responseOpts.redirectUri
    );
    const urlDecoded = decodeURI(uriResponse.bodyEncoded);
    const parsedData = parse(urlDecoded);
    expect(parsedData.id_token).toBeDefined();
    expect(parsedData.state).toBeDefined();
    expect(parsedData.state).toStrictEqual(state);
    const authResponseToken = parsedData.id_token as string;
    const { payload } = decodeJwt(authResponseToken);

    // VERIFY DID AUTH RESPONSE
    const optsVerify: DidAuthVerifyOpts = {
      verificationType: {
        verifyUri: `${WALLET_API_BASE_URL}/api/v1/signature-validations`,
        authZToken,
        didUrlResolver: `${WALLET_API_BASE_URL}/api/v1/identifiers`,
      },
      nonce: (payload as DidAuthTypes.DidAuthResponsePayload).nonce,
      redirectUri: validationRequestResponse.payload.client_id as string,
    };
    const validationResponse = await verifyDidAuthResponse(
      authResponseToken,
      optsVerify
    );
    expect(validationResponse).toBeDefined();
    expect(validationResponse.signatureValidation).toBe(true);
  });
});
