import { parse } from "querystring";
import axios from "axios";
import {
  createDidAuthResponse,
  createUriResponse,
  DidAuthErrors,
  DidAuthTypes,
  DidAuthUtil,
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
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
      },
    };
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw an error BAD_PARAMS when no opts.nonce is passed", async () => {
    expect.assertions(1);
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
      },
      state,
    };
    await expect(createUriResponse(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });
  it("throw an error BAD_PARAMS when no opts.registrationType is passed", async () => {
    expect.assertions(1);
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
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
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
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
    const uriResponseDecoded = decodeURIComponent(uriResponse.urlEncoded);
    const splitUrl = uriResponseDecoded.split("#");
    const responseData = parse(splitUrl[1]);
    expect(responseData.id_token).toBeDefined();
    expect(responseData.state).toBeDefined();
    expect(responseData.state).toStrictEqual(state);
  });
  it("return a uriResponse with fragment when response_mode=fragment is passed", async () => {
    expect.assertions(3);
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
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
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
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
    const { hexPrivateKey, did } = mockedKeyAndDid();
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        hexPrivateKey,
        did,
        kid: `${did}#key-1`,
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

  it("throw Not implemented using external signature", async () => {
    expect.assertions(1);
    const state = DidAuthUtil.getState();
    const opts: DidAuthTypes.DidAuthResponseOpts = {
      redirectUri: "https://entity.example/demo",
      signatureType: {
        signatureUri: "https://localhost:8080/signature",
        did: "did:vid:0x29A9D0FDb033BFCb39B8E6CA2A63Bd1B0a2b80c4",
      },
      state,
      nonce: DidAuthUtil.getNonce(state),
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      did: "did:vid:0x29A9D0FDb033BFCb39B8E6CA2A63Bd1B0a2b80c4",
    };

    jest.spyOn(axios, "post").mockResolvedValue({
      status: 200,
      data: { jws: "a valid signature" },
    });
    await expect(createDidAuthResponse(opts)).rejects.toThrow(
      "Option not implemented"
    );
  });
});
