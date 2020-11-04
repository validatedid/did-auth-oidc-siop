/* eslint-disable import/prefer-default-export */
declare module "@validated-id/vid-did-resolver" {
  export function getResolver(options: {
    rpcUrl: string;
    registry: string;
  }): ResolverRegistry;
}
