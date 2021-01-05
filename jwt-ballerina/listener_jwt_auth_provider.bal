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

import ballerina/cache;
import ballerina/stringutils;

# Represents the listener JWT Auth provider, which authenticates by validating a JWT.
# ```ballerina
# jwt:ListenerJwtAuthProvider provider = new({
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
public class ListenerJwtAuthProvider {

    ValidatorConfig validatorConfig;

    # Provides authentication based on the provided JWT.
    #
    # + validatorConfig - JWT validator configurations
    public isolated function init(ValidatorConfig validatorConfig) {
        self.validatorConfig = validatorConfig;
        JwksConfig? jwksConfig = validatorConfig?.jwksConfig;
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

    # Authenticates provided JWT against `jwt:ValidatorConfig`.
    #```ballerina
    # boolean|auth:Error result = provider.authenticate("<credential>");
    # ```
    #
    # + credential - JWT to be authenticated
    # + return - `jwt:Payload` if authentication is successful or else an `auth:Error` if JWT validation failed
    public isolated function authenticate(string credential) returns Payload|Error {
        string[] jwtComponents = stringutils:split(credential, "\\.");
        if (jwtComponents.length() != 3) {
            return prepareError("Credential format does not match to JWT format.");
        }

        Payload|Error validationResult = validate(credential, self.validatorConfig);
        if (validationResult is Error) {
            return prepareError("JWT validation failed.", validationResult);
        }
        return <Payload>validationResult;
    }
}

isolated function preloadJwksToCache(JwksConfig jwksConfig) returns Error? {
    cache:Cache jwksCache = <cache:Cache>jwksConfig?.jwksCache;
    string|Error stringResponse = getJwksResponse(jwksConfig.url, jwksConfig.clientConfig);
    if (stringResponse is Error) {
        return prepareError("Failed to call JWKs endpoint to preload JWKs to the cache.", stringResponse);
    }
    json[] jwksArray = check getJwksArray(<string>stringResponse);
    foreach json jwk in jwksArray {
        cache:Error? cachedResult = jwksCache.put(<string>jwk.kid, jwk);
        if (cachedResult is cache:Error) {
            return prepareError("Failed to put JWK for the kid: " + <string>jwk.kid + " to the cache.", cachedResult);
        }
    }
}
