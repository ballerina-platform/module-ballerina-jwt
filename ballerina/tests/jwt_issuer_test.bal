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
isolated function testIssueJwtWithAllFields() returns Error? {
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
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiNWEwYjc1NC04OTVmLTQyNzktODg0My1iNzQ1ZTExYTU3ZTkifQ."));
    string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\", \"kid\":\"5a0b754-895f-4279-8843-b745e11a57e9\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"],";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSingleAud() returns Error? {
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
    string result = check issue(issuerConfig);
    string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":\"ballerina\",";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSingleAudAndAudAsArray() returns Error? {
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
    string result = check issue(issuerConfig);
    string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\"],";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithNoIssOrSub() returns Error? {
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
    string result = check issue(issuerConfig);
    string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string payload = "{\"aud\":[\"ballerina\", \"ballerinaSamples\"],";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithNoAudOrSub() returns Error? {
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
    string result = check issue(issuerConfig);
    string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\",";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithCustomClaims() returns Error? {
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
    string result = check issue(issuerConfig);
    string header = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"],";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithoutSignatureConfig() returns Error? {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600
    };
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJub25lIiwgInR5cCI6IkpXVCJ9."));
    string header = "{\"alg\":\"none\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmNone() returns Error? {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: NONE
        }
    };
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJub25lIiwgInR5cCI6IkpXVCJ9."));
    string header = "{\"alg\":\"none\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmRS384() returns Error? {
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
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJSUzM4NCIsICJ0eXAiOiJKV1QifQ."));
    string header = "{\"alg\":\"RS384\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmRS512() returns Error? {
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
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJSUzUxMiIsICJ0eXAiOiJKV1QifQ."));
    string header = "{\"alg\":\"RS512\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmHS256() returns Error? {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: HS256,
            config: "s3cr3t"
        }
    };
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJIUzI1NiIsICJ0eXAiOiJKV1QifQ."));
    string header = "{\"alg\":\"HS256\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmHS384() returns Error? {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: HS384,
            config: "s3cr3t"
        }
    };
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJIUzM4NCIsICJ0eXAiOiJKV1QifQ."));
    string header = "{\"alg\":\"HS384\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
}

@test:Config {}
isolated function testIssueJwtWithSigningAlgorithmHS512() returns Error? {
    IssuerConfig issuerConfig = {
        username: "John",
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        expTime: 600,
        signatureConfig: {
            algorithm: HS512,
            config: "s3cr3t"
        }
    };
    string result = check issue(issuerConfig);
    test:assertTrue(result.startsWith("eyJhbGciOiJIUzUxMiIsICJ0eXAiOiJKV1QifQ."));
    string header = "{\"alg\":\"HS512\", \"typ\":\"JWT\"}";
    string payload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, header, payload);
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
    if result is Error {
        assertContains(result, "Signing JWT requires keystore information or private key information.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testIssueJwtWithPrivateKey() returns Error? {
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
    string result = check issue(issuerConfig);
    string expectedHeader = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string expectedPayload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, expectedHeader, expectedPayload);
}

@test:Config {}
isolated function testIssueJwtWithEncryptedPrivateKey() returns Error? {
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
    string result = check issue(issuerConfig);
    string expectedHeader = "{\"alg\":\"RS256\", \"typ\":\"JWT\"}";
    string expectedPayload = "{\"iss\":\"wso2\", \"sub\":\"John\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]";
    assertDecodedJwt(result, expectedHeader, expectedPayload);
}

isolated function assertDecodedJwt(string jwt, string header, string payload) {
    string[] parts = regex:split(jwt, "\\.");
    // check header
    byte[]|Error headerDecodedResult = decodeBase64Url(parts[0]);
    if headerDecodedResult is byte[] {
        string|error resultHeader = 'string:fromBytes(headerDecodedResult);
        if resultHeader is string {
            test:assertEquals(header, resultHeader);
        } else {
            test:assertFail("Assertion failed. Expected string, but found error.");
        }
    } else {
        test:assertFail("Assertion failed. Expected byte[], but found error.");
    }
    // check payload
    byte[]|Error payloadDecodedResult = decodeBase64Url(parts[1]);
    if payloadDecodedResult is byte[] {
        string|error resultPayload = 'string:fromBytes(payloadDecodedResult);
        if resultPayload is string {
            test:assertTrue(resultPayload.startsWith(payload));
        } else {
            test:assertFail("Assertion failed. Expected string, but found error.");
        }
    } else {
        test:assertFail("Assertion failed. Expected byte[], but found error.");
    }
}
