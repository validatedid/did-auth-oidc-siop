# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0](https://github.com/validatedid/did-auth-oidc-siop/compare/v2.0.0...v2.1.0) (2020-11-26)

### 🚀 Features

- implemented full siop response token validation ([03952ef](https://github.com/validatedid/did-auth-oidc-siop/commit/03952efe8ed63fe785e4d9a1e4e7f7ef1e30f251))
- using external identifier to obtain jwk public key ([70a14a1](https://github.com/validatedid/did-auth-oidc-siop/commit/70a14a1abcd64273357fd1b901586af48c51ca1d))

## [2.0.0](https://github.com/validatedid/did-auth-oidc-siop/compare/v0.0.5...v2.0.0) (2020-11-14)

### ⚠ BREAKING CHANGES

- library calls have different signatures input/output parameters

!! Be careful to update library to this version. Read the README and adapt your project accordingly.

### 🐛 Bug Fixes

- export OidcClaim type. solves issue: https://github.com/validatedid/did-auth-oidc-siop/issues/7 ([97f4718](https://github.com/validatedid/did-auth-oidc-siop/commit/97f47184514916943a1670500d83df077683d326))
- readme issue https://github.com/validatedid/did-auth-oidc-siop/issues/8 ([4ee901b](https://github.com/validatedid/did-auth-oidc-siop/commit/4ee901bce5f44a8d893e11b446a182f0ecbef8ae))

### 🚀 Features

- added complete Request Object parameters ([2be050b](https://github.com/validatedid/did-auth-oidc-siop/commit/2be050b3df99098ba62f784cdabed78b499a04f4))
- extended support from node.js v10 ([bd52b64](https://github.com/validatedid/did-auth-oidc-siop/commit/bd52b645277420cd321bdf489e11a53a187b179c))
- implemented sub and sub_jwk on Response Object ([6a8ca55](https://github.com/validatedid/did-auth-oidc-siop/commit/6a8ca55dae3e53ea6eda1db865e6370f7b27bd7a))
- update library to full compliant specs ([478d577](https://github.com/validatedid/did-auth-oidc-siop/commit/478d57723b7a30543aeeec2c6497c82f273a2c34))

- Merge pull request #9 from validatedid/feat/vid-1159-support-response-methods ([50a7d40](https://github.com/validatedid/did-auth-oidc-siop/commit/50a7d4068cbc7e78d724f75be70a920c5adb2798)), closes [#9](https://github.com/validatedid/did-auth-oidc-siop/issues/9) [#9](https://github.com/validatedid/did-auth-oidc-siop/issues/9)

### [0.0.6](https://github.com/validatedid/did-auth-oidc-siop/compare/v0.0.1...v0.0.6) (2020-11-06)
