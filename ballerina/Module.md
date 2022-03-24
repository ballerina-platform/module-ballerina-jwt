## Overview

This module provides a framework for authentication/authorization with JWTs and generation/validation of JWTs as specified in the [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), and [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).

JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure enabling the claims to be signed digitally or protecting the integrity with a Message Authentication Code(MAC) and/or encrypted.

The Ballerina `jwt` module facilitates auth providers that are to be used by the clients and listeners of different protocol connectors. Also, it provides the APIs for issuing a self-signed JWT and validating a JWT.

### Listener JWT Auth provider

Represents the listener JWT Auth provider, which is used to authenticate the provided credentials (JWT) against the provided JWT validator configurations.

### Client JWT Auth provider

Represents the client JWT Auth provider, which is used to authenticate with an external endpoint by issuing a self-signed JWT against the provided JWT issuer configurations.

### JWT issuer

A self-signed JWT can be issued with the provided configurations using this API as follows:

```ballerina
jwt:IssuerConfig issuerConfig = {
    username: "ballerina",
    issuer: "wso2",
    audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
    expTime: 3600,
    signatureConfig: {
        config: {
            keyFile: "/path/to/private.key"
        }
    }
};

string jwt = check jwt:issue(issuerConfig);
```

### JWT validator

A JWT can be validated with the provided configurations using the API as follows:

```ballerina
string jwt = "eyJ0eXAiOiJKV1QiLA0KI[...omitted for brevity...]mB92K27uhbwW1gFWFOEjXk";

jwt:ValidatorConfig validatorConfig = {
    issuer: "wso2",
    audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
    clockSkew: 60,
    signatureConfig: {
        certFile: "/path/to/public.crt"
    }
};

jwt:Payload result = check jwt:validate(jwt, validatorConfig);
```
