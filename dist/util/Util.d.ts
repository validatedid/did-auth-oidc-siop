import * as JWK from "./JWK";
declare function getNonce(): string;
declare function getHexPrivateKey(key: JWK.Key): string;
declare function getDIDFromKey(key: JWK.ECKey): string;
declare const base64urlEncodeBuffer: (buf: {
    toString: (arg0: string) => any;
}) => string;
declare function getECKeyfromHexPrivateKey(hexPrivateKey: string): {
    x: string;
    y: string;
};
declare function doPostCallWithToken(url: string, data: any, token: string): Promise<any>;
export { getNonce, getDIDFromKey, getHexPrivateKey, doPostCallWithToken, base64urlEncodeBuffer, getECKeyfromHexPrivateKey, };
//# sourceMappingURL=Util.d.ts.map