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

import ballerina/lang.'string;
import ballerina/regex;
import ballerina/test;

@test:Config {}
isolated function testIssueJwt() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        jwtId: "JlbmMiOiJBMTI4Q0JDLUhTMjU2In",
        keyId: "5a0b754-895f-4279-8843-b745e11a57e9",
        customClaims: { "scp": "hello" },
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        test:assertTrue(result.startsWith("eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiNWEwYjc1NC04OTVmLTQyNzktODg0My1iNzQ1ZTExYTU3ZTkifQ."));
        string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\", \"kid\":\"5a0b754-895f-4279-8843-b745e11a57e9\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"], \"jti\":\"JlbmMiOiJBMTI4Q0JDLUhTMjU2In\",";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithSingleAud() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: "ballerina",
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":\"ballerina\",";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithSingleAudAndAudAsArray() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina"],
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\"],";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithNoIssOrSub() {
    IssuerConfig issuerConfig = {
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string payload = "{\"aud\":[\"ballerina\", \"ballerinaSamples\"],";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithNoAudOrSub() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\",";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithCustomClaims() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        customClaims: { "scope": "test-scope" },
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"],";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithoutSignatureConfig() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600
    };

    string|Error result = issue(issuerConfig);
    if (result is string) {
        test:assertTrue(result.startsWith("eyJhbGciOiJub25lIiwgInR5cCI6IkpXVCJ9."));
        string header = "{\"alg\":\"none\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmNone() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: NONE
        }
    };

    string|Error result = issue(issuerConfig);
    if (result is string) {
        test:assertTrue(result.startsWith("eyJhbGciOiJub25lIiwgInR5cCI6IkpXVCJ9."));
        string header = "{\"alg\":\"none\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmRS384() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: RS384,
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        test:assertTrue(result.startsWith("eyJhbGciOiJSUzM4NCIsICJ0eXAiOiJKV1QifQ."));
        string header = "{\"alg\":\"RS384\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmRS512() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: RS512,
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

    string|Error result = issue(issuerConfig);
    if (result is string) {
        test:assertTrue(result.startsWith("eyJhbGciOiJSUzUxMiIsICJ0eXAiOiJKV1QifQ."));
        string header = "{\"alg\":\"RS512\", \"typ\":\"JWT\"}";
        string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
        assertDecodedJwt(result, header, payload);
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithoutSigningKeyInformation() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: RS256
        }
    };

    string|Error result = issue(issuerConfig);
    if (result is Error) {
        assertContains(result, "Signing JWT requires keystore information or private key information.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
isolated function testIssueJwtWithPrivateKey() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            config: {
                keyFile: PRIVATE_KEY_PATH
            }
        }
    };

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string expectedHeader = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string expectedPayload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
        assertDecodedJwt(result, expectedHeader, expectedPayload);

        ValidatorConfig validatorConfig = {
            issuer: "wso2",
            audience: ["ballerina", "ballerinaSamples"],
            clockSkew: 60,
            signatureConfig: {
                certFile: PUBLIC_CERT_PATH
            }
        };
        Payload|Error payload = validate(result, validatorConfig);
        if (payload is Error) {
            string? errMsg = payload.message();
            test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
        }
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

@test:Config {}
isolated function testIssueJwtWithEncryptedPrivateKey() {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            config: {
                keyFile: ENCRYPTED_PRIVATE_KEY_PATH,
                keyPassword: "ballerina"
            }
        }
    };

    string|Error result = issue(issuerConfig);
    if (result is string) {
        string expectedHeader = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
        string expectedPayload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
        assertDecodedJwt(result, expectedHeader, expectedPayload);

        ValidatorConfig validatorConfig = {
            issuer: "wso2",
            audience: ["ballerina", "ballerinaSamples"],
            clockSkew: 60,
            signatureConfig: {
                certFile: PUBLIC_CERT_PATH
            }
        };
        Payload|Error payload = validate(result, validatorConfig);
        if (payload is Error) {
            string? errMsg = payload.message();
            test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT.");
        }
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT.");
    }
}

isolated function assertDecodedJwt(string jwt, string header, string payload) {
    string[] parts = regex:split(jwt, "\\.");

    // check header
    byte[]|Error headerDecodedResult = decodeBase64Url(parts[0]);
    if (headerDecodedResult is byte[]) {
        string|error resultHeader = 'string:fromBytes(headerDecodedResult);
        if (resultHeader is string) {
            test:assertEquals(header, resultHeader, msg = "Found unexpected header.");
        } else {
            test:assertFail(msg = "Expected string, but found error.");
        }
    } else {
        test:assertFail(msg = "Expected byte[], but found error.");
    }

    // check payload
    byte[]|Error payloadDecodedResult = decodeBase64Url(parts[1]);
    if (payloadDecodedResult is byte[]) {
        string|error resultPayload = 'string:fromBytes(payloadDecodedResult);
        if (resultPayload is string) {
            test:assertTrue(resultPayload.startsWith(payload), msg = "Found unexpected payload.");
        } else {
            test:assertFail(msg = "Expected string, but found error.");
        }
    } else {
        test:assertFail(msg = "Expected byte[], but found error.");
    }
}
