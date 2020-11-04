import VidDidAuth from "./VidDIDAuth";
import DidAuthErrors from "./Errors";

export {
  DidAuthRequestCall,
  DidAuthRequestPayload,
  DidAuthResponseCall,
  DidAuthResponsePayload,
  DidAuthKeyType,
  DidAuthKeyCurve,
  DidAuthKeyAlgo,
  DidAuthScope,
  DIdAuthResponseType,
  DidAuthResponseIss,
} from "./DIDAuth";

export { JWTClaims, JWTHeader } from "./JWT";

export { getHexPrivateKey, getDIDFromKey, getNonce } from "./util/Util";

export { VidDidAuth, DidAuthErrors };
