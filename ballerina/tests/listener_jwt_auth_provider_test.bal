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

// NOTE: All the tokens/credentials used in this test are dummy tokens/credentials and used only for testing purposes.

import ballerina/cache;
import ballerina/test;

@test:Config {}
isolated function testListenerJwtAuthProviderSuccess() returns Error? {
    ValidatorConfig jwtConfig = {
        issuer: "wso2",
        audience: "ballerina",
        cacheConfig: {
            capacity: 10,
            evictionFactor: 0.25,
            evictionPolicy: cache:LRU,
            defaultMaxAge: -1,
            cleanupInterval: 3600
        },
        signatureConfig: {
            trustStoreConfig: {
                trustStore: {
                    path: TRUSTSTORE_PATH,
                    password: "ballerina"
                },
                certAlias: "ballerina"
            }
        }
    };
    ListenerJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    Payload result = check jwtAuthProvider.authenticate(JWT1);
    test:assertEquals(result?.iss, "wso2");
    test:assertEquals(result?.aud, ["ballerina","ballerinaSamples"]);
    // Authenticate the token from the cache
    result = check jwtAuthProvider.authenticate(JWT1);
    test:assertEquals(result?.iss, "wso2");
    test:assertEquals(result?.aud, ["ballerina","ballerinaSamples"]);
}

@test:Config {
    groups: ["jwks"]
}
isolated function testListenerJwtAuthProviderSuccessWithJwk() returns Error? {
    ValidatorConfig jwtConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        cacheConfig: {
            capacity: 10,
            evictionFactor: 0.25,
            evictionPolicy: cache:LRU,
            defaultMaxAge: -1,
            cleanupInterval: 3600
        },
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                cacheConfig: {
                    capacity: 10,
                    evictionFactor: 0.25,
                    evictionPolicy: cache:LRU,
                    defaultMaxAge: -1,
                    cleanupInterval: 3600
                },
                clientConfig: {
                    secureSocket: {
                        cert: {
                            path: TRUSTSTORE_PATH,
                            password: "ballerina"
                        }
                    }
                }
            }
        }
    };
    ListenerJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    Payload result = check jwtAuthProvider.authenticate(JWT2);
    test:assertEquals(result?.iss, "ballerina");
    test:assertEquals(result?.aud, ["vEwzbcasJVQm1jVYHUHCjhxZ4tYa"]);
}

@test:Config {}
isolated function testListenerJwtAuthProviderFailure() {
    ValidatorConfig jwtConfig = {
        issuer: "invalid",
        audience: "ballerina",
        signatureConfig: {
            trustStoreConfig: {
                trustStore: {
                    path: TRUSTSTORE_PATH,
                    password: "ballerina"
                },
                certAlias: "ballerina"
            }
        }
    };
    ListenerJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    Payload|Error result = jwtAuthProvider.authenticate(JWT1);
    if result is Error {
        test:assertEquals(result.message(), "JWT validation failed.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testListenerJwtAuthProviderFailureWithInvalidCredential() {
    ValidatorConfig jwtConfig = {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            trustStoreConfig: {
                trustStore: {
                    path: TRUSTSTORE_PATH,
                    password: "ballerina"
                },
                certAlias: "ballerina"
            }
        }
    };
    ListenerJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    Payload|Error result = jwtAuthProvider.authenticate("invalid_credential");
    if result is Error {
        test:assertEquals(result.message(), "Credential format does not match to JWT format.");
    } else {
        test:assertFail("Expected error not found.");
    }
}
