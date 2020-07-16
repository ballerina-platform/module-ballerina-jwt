// Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import ballerina/cache;
import ballerina/http;
import ballerina/stringutils;

# Represents the inbound JWT auth provider, which authenticates by validating a JWT.
# The `jwt:InboundJwtAuthProvider` is another implementation of the `auth:InboundAuthProvider` interface.
# ```ballerina
# jwt:InboundJwtAuthProvider inboundJwtAuthProvider = new({
#     issuer: "example",
#     audience: "ballerina",
#     signatureConfig: {
#         certificateAlias: "ballerina",
#         trustStore: {
#             path: "/path/to/truststore.p12",
#             password: "ballerina"
#         }
#     }
# });
# ```
#
public type InboundJwtAuthProvider object {

    *auth:InboundAuthProvider;

    JwtValidatorConfig jwtValidatorConfig;

    # Provides authentication based on the provided JWT.
    #
    # + jwtValidatorConfig - JWT validator configurations
    public function init(JwtValidatorConfig jwtValidatorConfig) {
        self.jwtValidatorConfig = jwtValidatorConfig;
        JwksConfig? jwksConfig = jwtValidatorConfig?.jwksConfig;
        if (jwksConfig is JwksConfig) {
            cache:Cache? jwksCache = jwksConfig?.jwksCache;
            if (jwksCache is cache:Cache) {
                Error? result = preloadJwksToCache(jwksConfig);
                if (result is Error) {
                    panic result;
                }
            }
        }
    }

# Authenticates provided JWT against `jwt:JwtValidatorConfig`.
#```ballerina
# boolean|auth:Error result = inboundJwtAuthProvider.authenticate("<credential>");
# ```
#
# + credential - JWT to be authenticated
# + return - `true` if authentication is successful, `false` otherwise or else an `auth:Error` if JWT validation failed
    public function authenticate(string credential) returns @tainted (boolean|auth:Error) {
        string[] jwtComponents = stringutils:split(credential, "\\.");
        if (jwtComponents.length() != 3) {
            return false;
        }

        JwtPayload|Error validationResult = validateJwt(credential, self.jwtValidatorConfig);
        if (validationResult is JwtPayload) {
            setInvocationContext(credential, validationResult);
            return true;
        } else {
            return prepareAuthError("JWT validation failed.", validationResult);
        }
    }
};

function preloadJwksToCache(JwksConfig jwksConfig) returns @tainted Error? {
    cache:Cache jwksCache = <cache:Cache>jwksConfig?.jwksCache;
    http:Client jwksClient = new(jwksConfig.url, jwksConfig.clientConfig);
    http:Response|http:ClientError response = jwksClient->get("");
    if (response is http:Response) {
        json|http:ClientError result = response.getJsonPayload();
        if (result is http:ClientError) {
            return prepareError(result.message(), result);
        }
        json payload = <json>result;
        json[] jwks = <json[]>payload.keys;
        foreach json jwk in jwks {
            cache:Error? cachedResult = jwksCache.put(<string>jwk.kid, jwk);
            if (cachedResult is cache:Error) {
                return prepareError("Failed to put JWK for the kid: " + <string>jwk.kid + " to the cache.", cachedResult);
            }
        }
    } else {
        return prepareError("Failed to call JWKs endpoint to preload JWKs to the cache.", response);
    }
}

function setInvocationContext(string credential, JwtPayload jwtPayload) {
    string? sub = jwtPayload?.sub;
    // By default set sub as username.
    string username = (sub is () ? "" : sub);
    auth:setInvocationContext("jwt", credential, username);
    map<json>? claims = jwtPayload?.customClaims;
    if (claims is map<json>) {
        auth:setInvocationContext(claims = claims);
        if (claims.hasKey("scope")) {
            json scopeString = claims["scope"];
            if (scopeString is string && scopeString != "") {
                auth:setInvocationContext(scopes = stringutils:split(scopeString, " "));
            }
        }
    }
}
