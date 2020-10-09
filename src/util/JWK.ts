import { KeyObject } from "crypto";

export type use = "sig" | "enc";
export type keyOperation =
  | "sign"
  | "verify"
  | "encrypt"
  | "decrypt"
  | "wrapKey"
  | "unwrapKey"
  | "deriveKey";
export type asymmetricKeyObjectTypes = "private" | "public";
export type keyObjectTypes = asymmetricKeyObjectTypes | "secret";
export type keyType = "RSA" | "EC" | "OKP" | "oct";

export interface BasicParameters {
  alg?: string;
  use?: use;
  kid?: string;
  key_ops?: keyOperation[];
}

export interface KeyParameters extends BasicParameters {
  x5c?: string[];
  x5t?: string;
  "x5t#S256"?: string;
}

export type ECCurve = "P-256" | "secp256k1" | "P-384" | "P-521";

export interface JWKECKey extends KeyParameters {
  kty: "EC";
  crv: ECCurve;
  x: string;
  y: string;
  d?: string;
}

export interface Key {
  readonly private: boolean;
  readonly public: boolean;
  readonly secret: boolean;
  readonly type: keyObjectTypes;

  readonly kty: keyType;
  readonly alg?: string;
  readonly use?: use;
  readonly key_ops?: ReadonlyArray<keyOperation>;
  readonly kid: string;
  readonly thumbprint: string;
  readonly x5c?: ReadonlyArray<string>;
  readonly x5t?: string;
  readonly "x5t#S256"?: string;
  readonly keyObject: KeyObject;

  readonly crv?: ECCurve;
  readonly d?: string;
  readonly dp?: string;
  readonly dq?: string;
  readonly e?: string;
  readonly k?: string;
  readonly n?: string;
  readonly p?: string;
  readonly q?: string;
  readonly qi?: string;
  readonly x?: string;
  readonly y?: string;

  algorithms(operation?: keyOperation): Set<string>;
}

export interface ECKey extends Key {
  readonly secret: false;
  readonly type: asymmetricKeyObjectTypes;

  readonly kty: "EC";

  readonly crv: ECCurve;
  readonly x: string;
  readonly y: string;
  readonly d?: string;

  readonly dp: undefined;
  readonly dq: undefined;
  readonly e: undefined;
  readonly k: undefined;
  readonly n: undefined;
  readonly p: undefined;
  readonly q: undefined;
  readonly qi: undefined;

  toJWK(privateKey?: boolean): JWKECKey;
}
