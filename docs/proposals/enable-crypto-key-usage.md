# Proposal: Enable direct use of `crypto:PrivateKey` and `crypto:PublicKey` in JWT signature configurations

_Authors_: @ayeshLK \
_Reviewers_: @daneshk @NipunaRanasinghe @Bhashinee \
_Created_: 2024/05/08 \
_Updated_: 2024/05/08 \
_Issue_: [#6515](https://github.com/ballerina-platform/ballerina-library/issues/6515)

## Summary

JWT signature configurations are designed to facilitate the generation and verification of JWT signatures. 
Therefore, the JWT package should support direct usage of `crypto:PrivateKey` and `crypto:PublicKey` in 
`jwt:IssuerSignatureConfig` and `jwt:ValidatorSignatureConfig` respectively.


## Goals

- Enable direct use of `crypto:PrivateKey` and `crypto:PublicKey` in JWT signature configurations

## Motivation

JWT signature configurations are required configurations to generate the signature portion of a JWT. Typically, 
these configurations involve a private key and a public certificate. In Ballerina, these elements are represented as 
`crypto:PrivateKey` and `crypto:PublicKey`, respectively. Therefore, JWT signature configurations should allow the 
direct usage of `crypto:PrivateKey` and `crypto:PublicKey` within its API.

## Description

As mentioned in the Goals section the purpose of this proposal is to enable direct use of `crypto:PrivateKey` 
and `crypto:PublicKey` in JWT signature configurations.

The key functionalities expected from this change are as follows,

- Allow `crypto:PrivateKey` and `crypto:PublicKey` in `jwt:IssuerSignatureConfig` and `jwt:ValidatorSignatureConfig` respectively.

### API changes

Add support for `crypto:PrivateKey` in the `config` field of `jwt:IssuerSignatureConfig` record.

```ballerina
# Represents JWT signature configurations.
#
# + algorithm - Cryptographic signing algorithm for JWS
# + config - KeyStore configurations, private key configurations or shared key configurations
public type IssuerSignatureConfig record {|
    SigningAlgorithm algorithm = RS256;
    record {|
        crypto:KeyStore keyStore;
        string keyAlias;
        string keyPassword;
    |} | record {|
        string keyFile;
        string keyPassword?;
    |}|crypto:PrivateKey|string config?;
|};
```

Add support for `crypto:PublicKey` in the `certFile` field of `jwt:ValidatorSignatureConfig` record.

```ballerina
# Represents JWT signature configurations.
#
# + jwksConfig - JWKS configurations
# + certFile - Public certificate file
# + trustStoreConfig - JWT TrustStore configurations
# + secret - HMAC secret configuration
public type ValidatorSignatureConfig record {|
    record {|
        string url;
        cache:CacheConfig cacheConfig?;
        ClientConfiguration clientConfig = {};
    |} jwksConfig?;
    string|crypto:PublicKey certFile?;
    record {|
        crypto:TrustStore trustStore;
        string certAlias;
    |} trustStoreConfig?;
    string secret?;
|};
```

## Dependencies

- [#6513](https://github.com/ballerina-platform/ballerina-library/issues/6513)
