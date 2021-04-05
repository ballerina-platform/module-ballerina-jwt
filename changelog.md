# Change Log
This file contains all the notable changes done to the Ballerina JWT package through the releases.

## [1.1.0-alpha6] - 2021-04-02

### Changed
- [Remove usages of checkpanic for type narrowing](https://github.com/ballerina-platform/module-ballerina-jwt/pull/153)

## [1.1.0-alpha5] - 2021-03-19

### Added
- [Add cert file and mTLS support for JDK11 client](https://github.com/ballerina-platform/module-ballerina-jwt/pull/137)
- [Add jti claim as a user input](https://github.com/ballerina-platform/module-ballerina-jwt/pull/144)

### Changed
- [Replace base64 URL encode/decode APIs](https://github.com/ballerina-platform/module-ballerina-jwt/pull/129)
- [Update error types and log API](https://github.com/ballerina-platform/module-ballerina-jwt/pull/139)
- [Update for Time API changes](https://github.com/ballerina-platform/module-ballerina-jwt/pull/142)

### Fixed
- [Fix nbf/exp claim validation](https://github.com/ballerina-platform/module-ballerina-jwt/pull/145)

## [1.1.0-alpha4] - 2021-02-20

### Changed
- [Refactor JWT validating API](https://github.com/ballerina-platform/module-ballerina-jwt/pull/105)
- [Refactor JWT issue/validate test cases](https://github.com/ballerina-platform/module-ballerina-jwt/pull/106)
- [Update for crypto API changes](https://github.com/ballerina-platform/module-ballerina-jwt/pull/108)
- [Extend private key/public cert support for JWT signature generation/validation](https://github.com/ballerina-platform/module-ballerina-jwt/pull/109)
