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

isolated function jwtDataProvider() returns string {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            config: {
                keyStore: {
                    path: KEYSTORE_PATH,
                    password: "ballerina"
                },
                keyAlias: "ballerina",
                keyPassword: "ballerina"
            }
        }
    };
    string|Error token = issue(issuerConfig);
    if (token is string) {
        return token;
    } else {
        panic token;
    }
}

@test:Config {}
isolated function testValidateJwt() {
    string jwt = jwtDataProvider();
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
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithSingleAud() {
    string jwt = jwtDataProvider();
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
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithSingleAudAndAudAsArray() {
    string jwt = jwtDataProvider();
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
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithNoIssOrSub() {
    string jwt = jwtDataProvider();
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
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtWithInvalidSignature() {
    string jwt = jwtDataProvider();
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
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithJwk() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0Tk" +
                 "RObFpEVTFPR0ZrTmpGaU1RIn0.eyJzdWIiOiJhZG1pbiIsICJpc3MiOiJiYWxsZXJpbmEiLCAiZXhwIjoxOTA3NjY1NzQ2LCAi" +
                 "anRpIjoiMTAwMDc4MjM0YmEyMyIsICJhdWQiOlsidkV3emJjYXNKVlFtMWpWWUhVSENqaHhaNHRZYSJdfQ.E8E7VO18V6MG7Ns" +
                 "87Y314Dqg8RYOMe0WWYlSYFhSv0mHkJQ8bSSyBJzFG0Se_7UsTWFBwzIALw6wUiP7UGraosilf8k6HGJWbTjWtLXfniJXx5Ncz" +
                 "ikzciG8ADddksm-0AMi5uPsgAQdg7FNaH9f4vAL6SPMEYp2gN6GDnWTH7M1vnknwjOwTbQpGrPu_w2V1tbsBwSzof3Fk_cYrnt" +
                 "u8D_pfsBu3eqFiJZD7AXUq8EYbgIxpSwvdi6_Rvw2_TAi46drouxXK2Jglz_HvheUVCERT15Y8JNJONJPJ52MsN6t297hyFV9A" +
                 "myNPzwHxxmi753TclbapDqDnVPI1tpc-Q";
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://asb0zigfg2.execute-api.us-west-2.amazonaws.com/v1/jwks"
            }
        }
    };
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithJwkWithValidTrustStore() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0Tk" +
                 "RObFpEVTFPR0ZrTmpGaU1RIn0.eyJzdWIiOiJhZG1pbiIsICJpc3MiOiJiYWxsZXJpbmEiLCAiZXhwIjoxOTA3NjY1NzQ2LCAi" +
                 "anRpIjoiMTAwMDc4MjM0YmEyMyIsICJhdWQiOlsidkV3emJjYXNKVlFtMWpWWUhVSENqaHhaNHRZYSJdfQ.E8E7VO18V6MG7Ns" +
                 "87Y314Dqg8RYOMe0WWYlSYFhSv0mHkJQ8bSSyBJzFG0Se_7UsTWFBwzIALw6wUiP7UGraosilf8k6HGJWbTjWtLXfniJXx5Ncz" +
                 "ikzciG8ADddksm-0AMi5uPsgAQdg7FNaH9f4vAL6SPMEYp2gN6GDnWTH7M1vnknwjOwTbQpGrPu_w2V1tbsBwSzof3Fk_cYrnt" +
                 "u8D_pfsBu3eqFiJZD7AXUq8EYbgIxpSwvdi6_Rvw2_TAi46drouxXK2Jglz_HvheUVCERT15Y8JNJONJPJ52MsN6t297hyFV9A" +
                 "myNPzwHxxmi753TclbapDqDnVPI1tpc-Q";
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://asb0zigfg2.execute-api.us-west-2.amazonaws.com/v1/jwks",
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
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithJwkWithClientInvalidCertificate() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0Tk" +
                 "RObFpEVTFPR0ZrTmpGaU1RIn0.eyJzdWIiOiJhZG1pbiIsICJpc3MiOiJiYWxsZXJpbmEiLCAiZXhwIjoxOTA3NjY1NzQ2LCAi" +
                 "anRpIjoiMTAwMDc4MjM0YmEyMyIsICJhdWQiOlsidkV3emJjYXNKVlFtMWpWWUhVSENqaHhaNHRZYSJdfQ.E8E7VO18V6MG7Ns" +
                 "87Y314Dqg8RYOMe0WWYlSYFhSv0mHkJQ8bSSyBJzFG0Se_7UsTWFBwzIALw6wUiP7UGraosilf8k6HGJWbTjWtLXfniJXx5Ncz" +
                 "ikzciG8ADddksm-0AMi5uPsgAQdg7FNaH9f4vAL6SPMEYp2gN6GDnWTH7M1vnknwjOwTbQpGrPu_w2V1tbsBwSzof3Fk_cYrnt" +
                 "u8D_pfsBu3eqFiJZD7AXUq8EYbgIxpSwvdi6_Rvw2_TAi46drouxXK2Jglz_HvheUVCERT15Y8JNJONJPJ52MsN6t297hyFV9A" +
                 "myNPzwHxxmi753TclbapDqDnVPI1tpc-Q";
    ValidatorConfig validatorConfig = {
        issuer: "ballerina",
        audience: "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
        signatureConfig: {
            jwksConfig: {
                url: "https://asb0zigfg2.execute-api.us-west-2.amazonaws.com/v1/jwks",
                clientConfig: {
                    httpVersion: HTTP_2,
                    secureSocket: {
                        cert: PUBLIC_CERT_PATH
                    }
                }
            }
        }
    };
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        assertContains(result, "Failed to call JWKS endpoint 'https://asb0zigfg2.execute-api.us-west-2.amazonaws.com/v1/jwks'. Failed to send the request to the endpoint.");
    } else {
        test:assertFail(msg = "Error in validating JWT signature with invalid certificate.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithPublicCert() {
    string jwt = jwtDataProvider();
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        clockSkew: 60,
        signatureConfig: {
            certFile: PUBLIC_CERT_PATH
        }
    };
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
    }
}

@test:Config {}
isolated function testValidateJwtSignatureWithInvalidPublicCert() {
    string jwt = jwtDataProvider();
    ValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        clockSkew: 60,
        signatureConfig: {
            certFile: INVALID_PUBLIC_CERT_PATH
        }
    };
    Payload|Error result = validate(jwt, validatorConfig);
    if (result is Error) {
        assertContains(result, "Public key certificate validity period has passed.");
    } else {
        test:assertFail(msg = "Error in validating JWT signature with invalid public cert file.");
    }
}
