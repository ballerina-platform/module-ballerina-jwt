Ballerina JWT Library
===================

  [![Build](https://github.com/ballerina-platform/module-ballerina-jwt/workflows/Build/badge.svg)](https://github.com/ballerina-platform/module-ballerina-jwt/actions?query=workflow%3ABuild)
  [![GitHub Last Commit](https://img.shields.io/github/last-commit/ballerina-platform/module-ballerina-jwt.svg?label=Last%20Commit)](https://github.com/ballerina-platform/module-ballerina-jwt/commits/master)
  [![Github issues](https://img.shields.io/github/issues/ballerina-platform/ballerina-standard-library/module/jwt.svg?label=Open%20Issues)](https://github.com/ballerina-platform/ballerina-standard-library/labels/module%2Fjwt)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  [![codecov](https://codecov.io/gh/ballerina-platform/module-ballerina-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/ballerina-platform/module-ballerina-jwt)

The JWT library is one of the standard library modules of the <a target="_blank" href="https://ballerina.io/">Ballerina</a> language.

It provides a listener JWT authentication provider, which can be used to authenticate the provided credentials against the provided JWT validator configurations, and a client self-signed JWT authentication provider, which can be used to authenticate against an external endpoint with a self-signed JWT issued against the provided JWT issuer configurations. Also, this module provides the functionality related to issuing and validating a JWT.

For more information go to [The JWT Module](https://ballerina.io/learn/api-docs/ballerina/#/ballerina/jwt/latest/jwt/).

For example demonstrations of the usage, go to [Ballerina By Examples](https://ballerina.io/learn/by-example/).

## Issues and Projects

Issues and Projects tabs are disabled for this repository as this is part of the Ballerina Standard Library. To report bugs, request new features, start new discussions, view project boards, etc. please visit Ballerina Standard Library [parent repository](https://github.com/ballerina-platform/ballerina-standard-library).

This repository only contains the source code for the module.

## Building from the Source

### Setting Up the Prerequisites

1. Download and install Java SE Development Kit (JDK) version 11 (from one of the following locations).

   * [Oracle](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)
   
   * [OpenJDK](https://adoptopenjdk.net)
   
        > **Note:** Set the JAVA_HOME environment variable to the path name of the directory into which you installed JDK.

2. Export Github Personal Access Token (PAT) with read package permissions as follows:

    ```
    export packageUser=<Username>
    export packagePAT=<Personal Access Token>
    ```

### Building the Source

Execute the commands below to build from the source.

1. To build the library:
        
        ./gradlew clean build

2. To run the tests:

        ./gradlew clean test

3. To build the module without the tests:

        ./gradlew clean build -x test

4. To debug the tests:

        ./gradlew clean test -Pdebug=<port>

## Contributing to Ballerina

As an open source project, Ballerina welcomes contributions from the community.

For more information, go to the [contribution guidelines](https://github.com/ballerina-platform/ballerina-lang/blob/master/CONTRIBUTING.md).

## Code of Conduct

All contributors are encouraged to read the [Ballerina Code of Conduct](https://ballerina.io/code-of-conduct).

## Useful Links

* Discuss about code changes of the Ballerina project in [ballerina-dev@googlegroups.com](mailto:ballerina-dev@googlegroups.com).
* Chat live with us via our [Slack channel](https://ballerina.io/community/slack/).
* Post all technical questions on Stack Overflow with the [#ballerina](https://stackoverflow.com/questions/tagged/ballerina) tag.
