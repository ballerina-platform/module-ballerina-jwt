// Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/auth;
import ballerina/system;
import ballerina/time;

# Represents the outbound JWT auth provider, which is used to authenticate with an external endpoint by generating a JWT.
# The `jwt:OutboundJwtAuthProvider` is another implementation of the `auth:OutboundAuthProvider` interface.
# ```ballerina
# jwt:OutboundJwtAuthProvider jwtAuthProvider = new({
#     issuer: "example",
#     audience: ["ballerina"],
#     keyStoreConfig: {
#         keyAlias: "ballerina",
#         keyPassword: "ballerina",
#         keyStore: {
#             path: "/path/to/keystore.p12",
#             password: "ballerina"
#         }
#     }
# });
# ```
public class OutboundJwtAuthProvider {

    *auth:OutboundAuthProvider;

    JwtIssuerConfig? jwtIssuerConfig;

    # Provides authentication based on the provided JWT configuration.
    #
    # + jwtIssuerConfig - JWT issuer configurations
    public isolated function init(JwtIssuerConfig? jwtIssuerConfig = ()) {
        self.jwtIssuerConfig = jwtIssuerConfig;
    }

    # Generates the token for JWT authentication.
    # ```ballerina
    # string|auth:Error token = outboundJwtAuthProvider.generateToken();
    # ```
    #
    # + return - Generated token or else an `auth:Error` if token can't be generated
    public isolated function generateToken() returns string|auth:Error {
        string authToken = "";
        JwtIssuerConfig? jwtIssuerConfig = self.jwtIssuerConfig;
        if (jwtIssuerConfig is JwtIssuerConfig) {
            string|Error result = getJwtAuthToken(jwtIssuerConfig);
            if (result is error) {
                return prepareAuthError(result.message(), result);
            }
            authToken = <string>result;
        } else {
            string? token = auth:getInvocationContext()?.token;
            if (token is string) {
                authToken = token;
            }
        }
        if (authToken == "") {
            return prepareAuthError("JWT was not used during inbound authentication. Provide JwtIssuerConfig to issue new token.");
        }
        return authToken;
    }

    # Inspects the incoming data and generates the token for JWT authentication.
    #
    # + data - Map of data, which is extracted from the HTTP response
    # + return - JWT as `string`, `()` if nothing to be returned or else an `auth:Error` if token can't be generated
    public isolated function inspect(map<anydata> data) returns string|auth:Error? {
        return ();
    }
}

# Processes the auth token for JWT auth.
#
# + jwtIssuerConfig - JWT issuer configurations
# + return - JWT or else a `jwt:Error` if an error occurred while issuing JWT
isolated function getJwtAuthToken(JwtIssuerConfig jwtIssuerConfig) returns string|Error {
    JwtHeader header = { alg: jwtIssuerConfig.signingAlg, typ: "JWT" };
    string username;
    string? configUsername = jwtIssuerConfig?.username;
    if (configUsername is string) {
        username = configUsername;
    } else {
        string? userId = auth:getInvocationContext()?.userId;
        if (userId is string) {
            username = userId;
        } else {
            return prepareError("Failed to generate auth token since username is not provided at issuer config and the username is not defined at auth:getInvocationContext() record.");
        }
    }

    JwtPayload payload = {
        sub: username,
        iss: jwtIssuerConfig.issuer,
        exp: time:currentTime().time / 1000 + jwtIssuerConfig.expTimeInSeconds,
        iat: time:currentTime().time / 1000,
        nbf: time:currentTime().time / 1000,
        jti: system:uuid(),
        aud: jwtIssuerConfig.audience
    };

    map<json>? customClaims = jwtIssuerConfig?.customClaims;
    if (customClaims is map<json>) {
        payload.customClaims = customClaims;
    }

     // TODO: cache the token per-user per-client and reuse it
    return issueJwt(header, payload, jwtIssuerConfig.keyStoreConfig);
}
