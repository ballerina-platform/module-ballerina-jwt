Ballerina JWT Library
===================

  [![Build](https://github.com/ballerina-platform/module-ballerina-jwt/actions/workflows/build-timestamped-master.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-jwt/actions/workflows/build-timestamped-master.yml)
  [![codecov](https://codecov.io/gh/ballerina-platform/module-ballerina-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/ballerina-platform/module-ballerina-jwt)
  [![Trivy](https://github.com/ballerina-platform/module-ballerina-jwt/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-jwt/actions/workflows/trivy-scan.yml)
  [![GraalVM Check](https://github.com/ballerina-platform/module-ballerina-jwt/actions/workflows/build-with-bal-test-graalvm.yml/badge.svg)](https://github.com/ballerina-platform/module-ballerina-jwt/actions/workflows/build-with-bal-test-graalvm.yml)
  [![GitHub Last Commit](https://img.shields.io/github/last-commit/ballerina-platform/module-ballerina-jwt.svg?label=Last%20Commit)](https://github.com/ballerina-platform/module-ballerina-jwt/commits/master)
  [![GitHub issues](https://img.shields.io/github/issues/ballerina-platform/ballerina-standard-library/module/jwt.svg?label=Open%20Issues)](https://github.com/ballerina-platform/ballerina-standard-library/labels/module%2Fjwt)

This library provides a framework for authentication/authorization with JWTs and generation/validation of JWTs as specified in the [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515), and [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).

JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure enabling the claims to be signed digitally or protecting the integrity with a Message Authentication Code(MAC) and/or encrypted.

The Ballerina `jwt` library facilitates auth providers that are to be used by the clients and listeners of different protocol connectors. Also, it provides the APIs for issuing a self-signed JWT and validating a JWT.

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

## Issues and projects

Issues and Projects tabs are disabled for this repository as this is part of the Ballerina Standard Library. To report bugs, request new features, start new discussions, view project boards, etc., go to the [Ballerina Standard Library parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

This repository only contains the source code for the module.

## Build from the source

### Set up the prerequisites

1. Download and install Java SE Development Kit (JDK) version 17 (from one of the following locations).

   * [Oracle](https://www.oracle.com/java/technologies/downloads/)
   
   * [OpenJDK](https://adoptium.net)
   
        > **Note:** Set the `JAVA_HOME` environment variable to the path name of the directory into which you installed JDK.

2. Export your GitHub Personal Access Token (PAT) with the `read package` permission as follows:

    ```
    export packageUser=<Username>
    export packagePAT=<Personal Access Token>
    ```

3. Download and install [Docker](https://www.docker.com/).

### Build the source

Execute the commands below to build from the source.

1. To build the package:
    ```    
    ./gradlew clean build
    ```
2. To run the tests:
    ```
    ./gradlew clean test
    ```

3. To run a group of tests
    ```
    ./gradlew clean test -Pgroups=<test_group_names>
    ```

4. To build the without the tests:
    ```
    ./gradlew clean build -x test
    ```

5. To debug package implementation:
    ```
    ./gradlew clean build -Pdebug=<port>
    ```

6. To debug with Ballerina language:
    ```
    ./gradlew clean build -PbalJavaDebug=<port>
    ```

7. Publish the generated artifacts to the local Ballerina central repository:
    ```
    ./gradlew clean build -PpublishToLocalCentral=true
    ```

8. Publish the generated artifacts to the Ballerina central repository:
    ```
    ./gradlew clean build -PpublishToCentral=true
    ```

## Contribute to Ballerina

As an open source project, Ballerina welcomes contributions from the community.

For more information, go to the [contribution guidelines](https://github.com/ballerina-platform/ballerina-lang/blob/master/CONTRIBUTING.md).

## Code of conduct

All contributors are encouraged to read the [Ballerina Code of Conduct](https://ballerina.io/code-of-conduct).

## Useful links

* For more information go to the [`jwt` library](https://lib.ballerina.io/ballerina/jwt/latest).
* For example demonstrations of the usage, go to [Ballerina By Examples](https://ballerina.io/learn/by-example/).
* Chat live with us via our [Discord server](https://discord.gg/ballerinalang).
* Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.
