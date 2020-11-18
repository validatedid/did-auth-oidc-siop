import { parse } from "querystring";
import {
  createDidAuthRequest,
  createUriRequest,
  DidAuthErrors,
  DidAuthTypes,
} from "../../src";

describe("create uri Request tests should", () => {
  it("throw BAD_PARAMS when no opts is passed", async () => {
    expect.assertions(1);
    await expect(createUriRequest(undefined as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw BAD_PARAMS when no opts.redirectUri is passed", async () => {
    expect.assertions(1);
    const opts = {};
    await expect(createUriRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw BAD_PARAMS when no opts.requestObjectBy is passed", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "https://entity.example/demo",
    };
    await expect(createUriRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_PARAMS
    );
  });

  it("throw REQUEST_OBJECT_TYPE_NOT_SET when opts.requestObjectBy type is different from REFERENCE or VALUE", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "https://entity.example/demo",
      requestObjectBy: {
        type: "other type",
      },
    };
    await expect(createUriRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.REQUEST_OBJECT_TYPE_NOT_SET
    );
  });

  it("throw NO_REFERENCE_URI when opts.requestObjectBy type is REFERENCE and no referenceUri is passed", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "https://entity.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
      },
    };
    await expect(createUriRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.NO_REFERENCE_URI
    );
  });

  it("return a reference url", async () => {
    expect.assertions(12);
    const opts: DidAuthTypes.DidAuthRequestOpts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: "https://dev.vidchain.net/siop/jwts",
      },
      signatureType: {
        hexPrivateKey:
          "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
        did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1",
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };

    const uriRequest = await createUriRequest(opts);
    expect(uriRequest).toBeDefined();
    expect(uriRequest).toHaveProperty("urlEncoded");
    expect(uriRequest).toHaveProperty("encoding");
    expect(uriRequest).toHaveProperty("urlEncoded");
    const uriDecoded = decodeURIComponent(uriRequest.urlEncoded);
    expect(uriDecoded).toContain(`openid://`);
    expect(uriDecoded).toContain(
      `?response_type=${DidAuthTypes.DidAuthResponseType.ID_TOKEN}`
    );
    expect(uriDecoded).toContain(`&client_id=${opts.redirectUri}`);
    expect(uriDecoded).toContain(
      `&scope=${DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN}`
    );
    expect(uriDecoded).toContain(`&requestUri=`);
    const data = parse(uriDecoded);
    expect(data.requestUri).toStrictEqual(opts.requestObjectBy.referenceUri);
    expect(uriRequest).toHaveProperty("jwt");
    expect(uriRequest.jwt).toBeDefined();
  });

  it("return an url with an embedded token value", async () => {
    expect.assertions(10);
    const opts: DidAuthTypes.DidAuthRequestOpts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
      signatureType: {
        hexPrivateKey:
          "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
        did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1",
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };

    const uriRequest = await createUriRequest(opts);
    expect(uriRequest).toBeDefined();
    expect(uriRequest).toHaveProperty("urlEncoded");
    expect(uriRequest).toHaveProperty("encoding");
    expect(uriRequest).toHaveProperty("urlEncoded");
    const uriDecoded = decodeURIComponent(uriRequest.urlEncoded);
    expect(uriDecoded).toContain(`openid://`);
    expect(uriDecoded).toContain(
      `?response_type=${DidAuthTypes.DidAuthResponseType.ID_TOKEN}`
    );
    expect(uriDecoded).toContain(`&client_id=${opts.redirectUri}`);
    expect(uriDecoded).toContain(
      `&scope=${DidAuthTypes.DidAuthScope.OPENID_DIDAUTHN}`
    );
    expect(uriDecoded).toContain(`&request=`);
    const data = parse(uriDecoded);
    expect(data.request).toBeDefined();
  });
});

describe("create Did Auth Request tests should", () => {
  it("throw REQUEST_OBJECT_TYPE_NOT_SET when requestObjectBy type is different from REFERENCE and VALUE", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: "other type",
      },
      signatureType: {
        hexPrivateKey:
          "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
        did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1",
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };
    await expect(createDidAuthRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.REQUEST_OBJECT_TYPE_NOT_SET
    );
  });

  it("throw NO_REFERENCE_URI when no referenceUri is passed with REFERENCE requestObjectBy type is set", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
      },
      signatureType: {
        hexPrivateKey:
          "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
        did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1",
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };
    await expect(createDidAuthRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.NO_REFERENCE_URI
    );
  });

  it("throw BAD_SIGNATURE_PARAMS when signature Type is neither internal nor external", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: "https://dev.vidchain.net/siop/jwts",
      },
      signatureType: {},
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.VALUE,
      },
    };
    await expect(createDidAuthRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.BAD_SIGNATURE_PARAMS
    );
  });

  it("throw REGISTRATION_OBJECT_TYPE_NOT_SET when objectPassedBy type is neither REFERENCE nor VALUE", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: "https://dev.vidchain.net/siop/jwts",
      },
      signatureType: {
        hexPrivateKey:
          "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
        did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1",
      },
      registrationType: {
        type: "other type",
      },
    };
    await expect(createDidAuthRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.REGISTRATION_OBJECT_TYPE_NOT_SET
    );
  });

  it("throw NO_REFERENCE_URI when objectPassedBy type is REFERENCE and no referenceUri is passed", async () => {
    expect.assertions(1);
    const opts = {
      redirectUri: "http://app.example/demo",
      requestObjectBy: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
        referenceUri: "https://dev.vidchain.net/siop/jwts",
      },
      signatureType: {
        hexPrivateKey:
          "f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f",
        did: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0",
        kid: "did:vid:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#key-1",
      },
      registrationType: {
        type: DidAuthTypes.ObjectPassedBy.REFERENCE,
      },
    };
    await expect(createDidAuthRequest(opts as never)).rejects.toThrow(
      DidAuthErrors.NO_REFERENCE_URI
    );
  });
});
