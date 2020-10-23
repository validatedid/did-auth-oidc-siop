import { DidAuthRequestCall, DidAuthRequestPayload, DidAuthResponsePayload, DidAuthResponseCall, DidAuthValidationResponse } from "./DIDAuth";
export default class VidDidAuth {
    /**
     *
     * @param siopRequest
     */
    static createUriRequest(didAuthRequestCall: DidAuthRequestCall): Promise<{
        uri: string;
        nonce: string;
        jwt: string;
    }>;
    /**
     * Creates a DidAuth Request Object
     * @param didAuthRequestCall Request input data to build a signed DidAuth Request Token
     */
    static createDidAuthRequest(didAuthRequestCall: DidAuthRequestCall): Promise<{
        jwt: string;
        nonce: string;
    }>;
    /**
     * Verifies a DidAuth ID Request Token
     * @param didAuthJwt signed DidAuth Request Token
     * @param registry hexadecimal ddress where it is deployed the VID DID Smart Contract
     * @param rpcUrl URL for the VID DID Provider
     */
    static verifyDidAuthRequest(didAuthJwt: string, registry: string, rpcUrl: string): Promise<DidAuthRequestPayload>;
    /**
     * Creates a DidAuth Response Object
     * @param input Response input data to build a signed DidAuth Response Token
     */
    static createDidAuthResponse(didAuthResponseCall: DidAuthResponseCall): Promise<string>;
    /**
     * Verifies a DidAuth ID Response Token
     * @param didAuthJwt igned DidAuth Response Token
     * @param nonce nonce value sent in the Authentication Request
     */
    static verifyDidAuthResponse(didAuthJwt: string, verifyUri: string, authZToken: string, nonce: string): Promise<DidAuthValidationResponse>;
    private static createDidAuthRequestPayload;
    private static createDidAuthResponsePayload;
    static signDidAuthInternal(issuer: string, payload: DidAuthResponsePayload, hexPrivateKey: string): Promise<string>;
    static signDidAuthExternal(payload: DidAuthRequestPayload, signatureUri: string, authZToken: string): Promise<string>;
    private static getJWK;
    private static getThumbprint;
    static getAudience(jwt: string): string | undefined;
}
//# sourceMappingURL=VidDIDAuth.d.ts.map