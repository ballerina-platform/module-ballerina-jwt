# Change Log
This file contains all the notable changes done to the Ballerina JWT package through the releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0-beta.1] - 2021-05-06

### Changed
- [Improve test coverage](https://github.com/ballerina-platform/ballerina-standard-library/issues/1010)

## [1.1.0-alpha8] - 2021-04-22

### Changed
- [Improve error messages and log messages](https://github.com/ballerina-platform/ballerina-standard-library/issues/1242)

## [1.1.0-alpha6] - 2021-04-02

### Changed
- Remove usages of `checkpanic` for type narrowing

## [1.1.0-alpha5] - 2021-03-19

### Added
- [Add cert file and mTLS support for JDK11 client](https://github.com/ballerina-platform/ballerina-standard-library/issues/936)
- [Add jti claim as a user input](https://github.com/ballerina-platform/ballerina-standard-library/issues/1210)

### Changed
- [Replace base64 URL encode/decode APIs](https://github.com/ballerina-platform/ballerina-standard-library/issues/1212)
- Update error types and log API
- Update for Time API changes

### Fixed
- Fix nbf/exp claim validation

## [1.1.0-alpha4] - 2021-02-20

### Changed
- [Refactor JWT validating API](https://github.com/ballerina-platform/ballerina-standard-library/issues/1213)
- Refactor JWT issue/validate test cases
- Update for crypto API changes
- [Extend private key/public cert support for JWT signature generation/validation](https://github.com/ballerina-platform/ballerina-standard-library/issues/822)
