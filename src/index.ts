import VidDidAuth from "./VidDIDAuth";
import DIDAUTH_ERRORS from "./Errors";

export {
  DidAuthRequestCall,
  DidAuthRequestPayload,
  DidAuthResponseCall,
  DidAuthResponsePayload,
  DIDAUTH_KEY_TYPE,
  DIDAUTH_KEY_CURVE,
  DIDAUTH_KEY_ALGO,
  DIAUTHScope,
  DIAUTHResponseType,
  DIDAUTH_RESPONSE_ISS,
} from "./DIDAuth";

export { JWTClaims, JWTHeader } from "./JWT";

export { getHexPrivateKey, getDIDFromKey, getNonce } from "./util/Util";

export { VidDidAuth, DIDAUTH_ERRORS };
