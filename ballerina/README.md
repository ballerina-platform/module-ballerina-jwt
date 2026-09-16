## Overview

This module provides a framework for authentication and authorization with JWTs, including generating and validating JWTs as specified in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), and [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517), and defines auth providers for clients and listeners of different protocol connectors.

### Key Features

- Listener and Client JWT Auth providers
- Self-signed JWT issuance
- JWT validation

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
