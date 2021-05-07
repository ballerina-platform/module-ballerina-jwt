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

import ballerina/test;

@test:Config {}
isolated function testValidateJwt() {
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        clockSkew: 60,
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
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }

    result = validate(JWT3, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }

    result = validate(JWT4, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithSingleAud() {
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: "ballerina",
        clockSkew: 60,
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
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithSingleAudAndAudAsArray() {
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: "ballerina",
        clockSkew: 60,
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
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithNoIssOrSub() {
    ValidatorConfig validatorConfig = {
        audience: "ballerinaSamples",
        clockSkew: 60,
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
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithInvalidSignature() {
    ValidatorConfig validatorConfig = {
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
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithoutSecureSocket() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks"
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        assertContains(result, "Failed to send the request to the endpoint. PKIX path building failed:");
    } else {
        test:assertFail(msg = "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithSslDisabled() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        disable: true
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithEmptySecureSocket() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        assertContains(result, "Need to configure 'crypto:TrustStore' or 'cert' with client SSL certificates file.");
    } else {
        test:assertFail(msg = "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithValidTrustStore() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
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
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithValidCert() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        cert: PUBLIC_CERT_PATH
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithInvalidCert() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        cert: INVALID_PUBLIC_CERT_PATH
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        assertContains(result, "Failed to send the request to the endpoint. PKIX path building failed:");
    } else {
        test:assertFail(msg = "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithValidTrustStoreAndValidKeyStore() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        cert: {
                            path: TRUSTSTORE_PATH,
                            password: "ballerina"
                        },
                        key: {
                            path: KEYSTORE_PATH,
                            password: "ballerina"
                        }
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithValidCertsAndKey() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        cert: PUBLIC_CERT_PATH,
                        key: {
                            certFile: PUBLIC_CERT_PATH,
                            keyFile: PRIVATE_KEY_PATH
                        }
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {
    groups: ["jwks"]
}
isolated function testValidateJwtSignatureWithJwkWithValidCertsAndEncryptedKey() {
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://localhost:9445/oauth2/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        cert: PUBLIC_CERT_PATH,
                        key: {
                            certFile: PUBLIC_CERT_PATH,
                            keyFile: ENCRYPTED_PRIVATE_KEY_PATH,
                            keyPassword: "ballerina"
                        }
                    }
                }
            }
        }
    };
    Payload|Error result = validate(JWT2, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithPublicCert() {
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        clockSkew: 60,
        signatureConfig: {
            certFile: PUBLIC_CERT_PATH
        }
    };
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithInvalidPublicCert() {
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        clockSkew: 60,
        signatureConfig: {
            certFile: INVALID_PUBLIC_CERT_PATH
        }
    };
    Payload|Error result = validate(JWT1, validatorConfig);
    if (result is Error) {
        assertContains(result, "Public key certificate validity period has passed.");
    } else {
        test:assertFail(msg = "Error in validating JWT.");
    }
}
