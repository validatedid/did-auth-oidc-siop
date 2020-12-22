import DidAuthErrors from "./interfaces/Errors";
import * as OidcSsi from "./interfaces/oidcSsi";
import * as DidAuthTypes from "./interfaces/DIDAuth.types";
import { util, utilJwk } from "./util";

export {
  createUriRequest,
  createUriResponse,
  createDidAuthRequest,
  createDidAuthResponse,
  verifyDidAuthRequest,
  verifyDidAuthResponse,
} from "./SiopDidAuth";
export { JWTClaims, JWTHeader } from "./interfaces/JWT";
export { OidcClaim, OidcClaimRequest } from "./interfaces/oidcSsi";

export {
  DidAuthErrors,
  OidcSsi,
  DidAuthTypes,
  util as DidAuthUtil,
  utilJwk as DidAuthJwk,
};
