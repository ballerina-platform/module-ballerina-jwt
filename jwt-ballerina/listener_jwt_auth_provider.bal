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
import ballerina/log;
import ballerina/regex;
import ballerina/time;

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
    cache:Cache? jwtCache = ();
    cache:Cache? jwksCache = ();

    # Provides authentication based on the provided JWT.
    #
    # + validatorConfig - JWT validator configurations
    public isolated function init(ValidatorConfig validatorConfig) {
        self.validatorConfig = validatorConfig;
        cache:CacheConfig? jwtCacheConfig = validatorConfig?.cacheConfig;
        if (jwtCacheConfig is cache:CacheConfig) {
            self.jwtCache = new(jwtCacheConfig);
        }
        var jwksConfig = validatorConfig?.signatureConfig?.jwksConfig;
        if !(jwksConfig is ()) {
            string url = <string> jwksConfig?.url;
            ClientConfiguration clientConfig = <ClientConfiguration> jwksConfig?.clientConfig;
            cache:CacheConfig? jwksCacheConfig = jwksConfig?.cacheConfig;
            if (jwksCacheConfig is cache:CacheConfig) {
                self.jwksCache = new(jwksCacheConfig);
                Error? result = preloadJwksToCache(<cache:Cache> (self.jwksCache), url, clientConfig);
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
        string[] jwtComponents = regex:split(credential, "\\.");
        if (jwtComponents.length() != 3) {
            return prepareError("Credential format does not match to JWT format.");
        }

        cache:Cache? jwtCache = self.jwtCache;
        if (jwtCache is cache:Cache && jwtCache.hasKey(credential)) {
            Payload? payload = validateFromCache(jwtCache, credential);
            if (payload is Payload) {
                return payload;
            }
        }

        Payload|Error validationResult = validateJwt(credential, self.validatorConfig, self.jwksCache);
        if (validationResult is Payload) {
            if (jwtCache is cache:Cache) {
                addToCache(jwtCache, credential, validationResult);
            }
            return validationResult;
        } else {
            return prepareError("JWT validation failed.", validationResult);
        }
    }
}

isolated function preloadJwksToCache(cache:Cache jwksCache, string url, ClientConfiguration clientConfig) returns Error? {
    string|Error stringResponse = getJwksResponse(url, clientConfig);
    if (stringResponse is string) {
        json[] jwksArray = check getJwksArray(stringResponse);
        foreach json jwk in jwksArray {
            json|error kid = jwk.kid;
            if (kid is json) {
                cache:Error? cachedResult = jwksCache.put(kid.toJsonString(), jwk);
                if (cachedResult is cache:Error) {
                    return prepareError("Failed to put JWK for the kid '" + kid.toJsonString() + "' to the cache.", cachedResult);
                }
            } else {
                return prepareError("Failed to access 'kid' property from the JSON '" + jwk.toJsonString() + "'.", kid);
            }
        }
    } else {
        return prepareError("Failed to call JWKS endpoint to preload JWKS to the cache.", stringResponse);
    }
}

isolated function validateFromCache(cache:Cache jwtCache, string jwt) returns Payload? {
    any|cache:Error cachedResult = jwtCache.get(jwt);
    if (cachedResult is any) {
        Payload payload = <Payload> cachedResult;
        int? expTime = payload?.exp;
        // convert to current time and check the expiry time
        [int, decimal] currentTime = time:utcNow();
        if (expTime is () || expTime > currentTime[0]) {
            return payload;
        } else {
            cache:Error? result = jwtCache.invalidate(jwt);
            if (result is cache:Error) {
                log:printError("Failed to invalidate JWT from the cache.", 'error = result);
            }
        }
    } else {
        log:printError("Failed to retrieve JWT entry from the cache.", 'error = cachedResult);
    }
}

isolated function addToCache(cache:Cache jwtCache, string jwt, Payload payload) {
    cache:Error? result = jwtCache.put(jwt, payload);
    if (result is cache:Error) {
        log:printError("Failed to add JWT to the cache.", 'error = result);
        return;
    }
}
