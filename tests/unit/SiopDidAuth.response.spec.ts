import { parse } from "querystring";
import axios from "axios";
import { decodeJwt, createJwt, SimpleSigner } from "@validatedid/did-jwt";
import {
  createDidAuthResponse,
  createUriResponse,
  DidAuthErrors,
  DidAuthTypes,
  DidAuthUtil,
  JWTHeader,
  createDidAuthResponseObject,
} from "../../src";
import { mockedKeyAndDid } from "../AuxTest";

describe("SiopDidAuth creat Uri Response tests should", () => {
  it("throw an error BAD_PARAMS when no opts is passed", async () => {
    expect.assertions(1);
    await expect(createUriResponse(undefined as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw an error BAD_PARAMS when no opts.redirectUri is passed", async () => {
    expect.assertions(1);
    const opts = {};
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw an error BAD_PARAMS when no opts.signatureType is passed", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "https://entity.example/demo",
    };
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw an error BAD_PARAMS when no opts.state is passed", async () => {
    expect.assertions(1);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
    };
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw an error BAD_PARAMS when no opts.nonce is passed", async () => {
    expect.assertions(1);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      state,
    };
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });
  it("throw an error BAD_PARAMS when no opts.registrationType is passed", async () => {
    expect.assertions(1);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
    };
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("return a uriResponse when no response_mode is passed", async () => {
    expect.assertions(9);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
    };

    const uriResponse = await createUriResponse(opts);
    expect(uriResponse).toBeDefined();
    expect(uriResponse).toHaveProperty("urlEncoded");
    expect(uriResponse).toHaveProperty("encoding");
    expect(uriResponse).toHaveProperty("response_mode");
    expect(uriResponse.encoding).toStrictEqual(
      DidAuthTypes.UrlEncodingFormat.FORM_URL_ENCODED
    );
    expect(uriResponse.response_mode).toStrictEqual(
      DidAuthTypes.DidAuthResponseMode.FRAGMENT
    );
    const uriResponseDecoded = decodeURI(uriResponse.urlEncoded);
    const splitUrl = uriResponseDecoded.split("#");
    const responseData = parse(splitUrl[1]);
    expect(responseData.id_token).toBeDefined();
    expect(responseData.state).toBeDefined();
    expect(responseData.state).toStrictEqual(state);
  });
  it("return a uriResponse with fragment when response_mode=fragment is passed", async () => {
    expect.assertions(3);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
      responseMode: DidAuthTypes.DidAuthResponseMode.FRAGMENT,
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
    };

    const uriResponse = await createUriResponse(opts);
    expect(uriResponse).toBeDefined();
    expect(uriResponse).toHaveProperty("response_mode");
    expect(uriResponse.response_mode).toStrictEqual(
      DidAuthTypes.DidAuthResponseMode.FRAGMENT
    );
  });
  it("return a uriResponse with query when response_mode=query is passed", async () => {
    expect.assertions(3);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
      responseMode: DidAuthTypes.DidAuthResponseMode.QUERY,
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
    };

    const uriResponse = await createUriResponse(opts);
    expect(uriResponse).toBeDefined();
    expect(uriResponse).toHaveProperty("response_mode");
    expect(uriResponse.response_mode).toStrictEqual(
      DidAuthTypes.DidAuthResponseMode.QUERY
    );
  });
  it("return a uriResponse with form_post when response_mode=form_post is passed", async () => {
    expect.assertions(4);
    const { hexPrivateKey, did } = await mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#keys-1`,
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
      responseMode: DidAuthTypes.DidAuthResponseMode.FORM_POST,
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did,
    };
    const uriResponse = await createUriResponse(opts);
    expect(uriResponse).toBeDefined();
    expect(uriResponse).toHaveProperty("response_mode");
    expect(uriResponse.response_mode).toStrictEqual(
      DidAuthTypes.DidAuthResponseMode.FORM_POST
    );
    expect(uriResponse).toHaveProperty("bodyEncoded");
  });
});

describe("create Did Auth response tests should", () => {
  it("throw BAD_SIGNATURE_PARAMS when signatureType is neither internal nor external", async () => {
    expect.assertions(1);

    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {},
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };
    await expect(createDidAuthResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_SIGNATURE_PARAMS
    );
  });

  it("create a valid response token with external signature and registration by value", async () => {
    expect.assertions(4);
    const state = DidAuthUtil.getState();
    const did = "did:ethr:0x29A9D0FDb033BFCb39B8E6CA2A63Bd1B0a2b80c4";
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        signatureUri: `https://localhost:8080/api/v1/signatures`,
        did,
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
        referenceUri: `https://localhost:8080/api/v1/identifiers/${did}`,
      },
      did,
    };
    jest.spyOn(axios, "get").mockResolvedValue({
      data: {
        verificationMethod: [
          {
            publicKeyJwk: {
              kty: "EC",
              crv: "secp256k1",
              x:
                "62451c7a3e0c6e2276960834b79ae491ba0a366cd6a1dd814571212ffaeaaf5a",
              y:
                "1ede3d754090437db67eca78c1659498c9cf275d2becc19cdc8f1ef76b9d8159",
              kid: "JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
            },
          },
        ],
      },
    } as never);

    type DataInput = {
      payload: Record<string, unknown>;
    };

    jest
      .spyOn(axios, "post")
      .mockImplementation(async (_url: string, data: DataInput) => {
        // assign specific JWT header
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${did}#keys-1`,
        };
        const jws = await createJwt(
          data.payload,
          {
            issuer: did,
            alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
            signer: SimpleSigner(
              "278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f"
            ),
          },
          header
        );
        return Promise.resolve({
          status: 200,
          data: { jws },
        });
      });
    const response = await createDidAuthResponse(opts);
    expect(response).toBeDefined();
    const responsePayload = decodeJwt(response)
      .payload as DidAuthTypes.DidAuthResponsePayload;
    expect(responsePayload).toBeDefined();
    expect(responsePayload).toHaveProperty("sub");
    expect(responsePayload).toHaveProperty("sub_jwk");
  });
});

describe("create Did Auth response object tests should", () => {
  it("throw BAD_SIGNATURE_PARAMS when no identifier url is set", async () => {
    expect.assertions(1);

    const opts = {
      redirectUri: "https://entity.example/demo",
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };
    await expect(createDidAuthResponseObject(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("create a valid response token with external signature and registration by value", async () => {
    expect.assertions(3);
    const state = DidAuthUtil.getState();
    const did = "did:ethr:0x29A9D0FDb033BFCb39B8E6CA2A63Bd1B0a2b80c4";
    const opts: DidAuthTypes.DidAuthResponseOptsNoSignature = {
      redirectUri: "https://entity.example/demo",
      identifiersUri: `https://dev.vidchain.net/api/v1/identifiers/${did};transform-keys=jwks`,
      state,
      nonce: DidAuthUtil.getNonce(state),
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
        referenceUri: `https://localhost:8080/api/v1/identifiers/${did}`,
      },
      did,
    };
    jest.spyOn(axios, "get").mockResolvedValue({
      data: {
        verificationMethod: [
          {
            publicKeyJwk: {
              kty: "EC",
              crv: "secp256k1",
              x:
                "62451c7a3e0c6e2276960834b79ae491ba0a366cd6a1dd814571212ffaeaaf5a",
              y:
                "1ede3d754090437db67eca78c1659498c9cf275d2becc19cdc8f1ef76b9d8159",
              kid: "JTa8+HgHPyId90xmMFw6KRD4YUYLosBuWJw33nAuRS0=",
            },
          },
        ],
      },
    } as never);

    type DataInput = {
      payload: Record<string, unknown>;
    };

    jest
      .spyOn(axios, "post")
      .mockImplementation(async (_url: string, data: DataInput) => {
        // assign specific JWT header
        const header: JWTHeader = {
          alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
          typ: "JWT",
          kid: `${did}#keys-1`,
        };
        const jws = await createJwt(
          data.payload,
          {
            issuer: did,
            alg: DidAuthTypes.DidAuthKeyAlgorithm.ES256KR,
            signer: SimpleSigner(
              "278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f"
            ),
          },
          header
        );
        return Promise.resolve({
          status: 200,
          data: { jws },
        });
      });
    const response = await createDidAuthResponseObject(opts);
    expect(response).toBeDefined();
    expect(response).toHaveProperty("sub");
    expect(response).toHaveProperty("sub_jwk");
  });
});
