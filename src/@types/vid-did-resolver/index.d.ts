/* eslint-disable import/prefer-default-export */
declare module "@validated-id/vid-did-resolver" {
  import { DIDResolver } from "did-resolver";

  interface ResolverRegistry {
    [index: string]: DIDResolver;
  }

  export function getResolver(options: {
    rpcUrl: string;
    registry: string;
  }): ResolverRegistry;
}
