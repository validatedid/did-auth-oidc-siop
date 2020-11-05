import VidDidAuth from "./VidDIDAuth";
import DidAuthErrors from "./interfaces/Errors";

export {
  DidAuthRequestCall,
  DidAuthRequestPayload,
  DidAuthResponseCall,
  DidAuthResponsePayload,
  DidAuthKeyType,
  DidAuthKeyCurve,
  DidAuthKeyAlgo,
  DidAuthScope,
  DidAuthResponseType,
  DidAuthResponseIss,
} from "./interfaces/DIDAuth";

export { JWTClaims, JWTHeader } from "./interfaces/JWT";

export { getHexPrivateKey, getDIDFromKey, getNonce } from "./util/Util";

export { VidDidAuth, DidAuthErrors };
