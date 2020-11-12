import VidDidAuth from "./VidDIDAuth";
import DidAuthErrors from "./interfaces/Errors";
import * as OidcSsi from "./interfaces/oidcSsi";

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

export { OidcClaim, OidcClaimRequest } from "./interfaces/oidcSsi";

export { getHexPrivateKey, getDIDFromKey, getNonce } from "./util/Util";

export { VidDidAuth, DidAuthErrors, OidcSsi };
