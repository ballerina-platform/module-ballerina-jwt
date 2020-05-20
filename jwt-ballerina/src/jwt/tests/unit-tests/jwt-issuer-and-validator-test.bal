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

import ballerina/crypto;
import ballerina/encoding;
import ballerina/lang.'string as str;
import ballerina/stringutils;
import ballerina/test;
import ballerina/time;

@test:Config {
}
function testIssueJwt() {
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig config = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };

    JwtHeader jwtHeader = {};
    jwtHeader.alg = RS256;
    jwtHeader.typ = "JWT";

    JwtPayload payload = {};
    payload.sub = "John";
    payload.iss = "wso2";
    payload.jti = "100078234ba23";
    payload.aud = ["ballerina", "ballerinaSamples"];
    payload.exp = time:currentTime().time/1000 + 600;

    var results = issueJwt(jwtHeader, payload, config);
    if (results is string) {
        jwt2 = results;
        string[] parts = stringutils:split(results, "\\.");

        // check header
        var headerDecodedResults = encoding:decodeBase64Url(parts[0]);
        if (headerDecodedResults is byte[]) {
            var resultsHeader = str:fromBytes(headerDecodedResults);
            if (resultsHeader is string) {
                test:assertEquals("{\"alg\":\"RS256\", \"typ\":\"JWT\"}", resultsHeader, msg = "Found unexpected header");
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }

        // check payload
        var payloadDecodedResults = encoding:decodeBase64Url(parts[1]);
        if (payloadDecodedResults is byte[]) {
            var resultsPayload = str:fromBytes(payloadDecodedResults);
            if (resultsPayload is string) {
                test:assertTrue(resultsPayload.startsWith("{\"sub\":\"John\", \"iss\":\"wso2\", \""));
                test:assertTrue(resultsPayload.endsWith("\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]}"));
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }
    } else {
        string? errMsg = results.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testIssueJwt"]
}
function testIssueJwtWithSingleAud() {
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig config = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };

    JwtHeader jwtHeader = {};
    jwtHeader.alg = RS256;
    jwtHeader.typ = "JWT";

    JwtPayload payload = {};
    payload.sub = "John";
    payload.iss = "wso2";
    payload.jti = "100078234ba23";
    payload.aud = "ballerina";
    payload.exp = time:currentTime().time/1000 + 600;

    var results = issueJwt(jwtHeader, payload, config);
    if (results is string) {
        string[] parts = stringutils:split(results, "\\.");

        // check header
        var headerDecodedResults = encoding:decodeBase64Url(parts[0]);
        if (headerDecodedResults is byte[]) {
            var resultsHeader = str:fromBytes(headerDecodedResults);
            if (resultsHeader is string) {
                test:assertEquals("{\"alg\":\"RS256\", \"typ\":\"JWT\"}", resultsHeader, msg = "Found unexpected header");
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }

        // check payload
        var payloadDecodedResults = encoding:decodeBase64Url(parts[1]);
        if (payloadDecodedResults is byte[]) {
            var resultsPayload = str:fromBytes(payloadDecodedResults);
            if (resultsPayload is string) {
                test:assertTrue(resultsPayload.startsWith("{\"sub\":\"John\", \"iss\":\"wso2\", \""));
                test:assertTrue(resultsPayload.endsWith("\", \"aud\":\"ballerina\"}"));
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }
    } else {
        string? errMsg = results.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testIssueJwtWithSingleAud"]
}
function testIssueJwtWithSingleAudAndAudAsArray() {
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig config = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };

    JwtHeader jwtHeader = {};
    jwtHeader.alg = RS256;
    jwtHeader.typ = "JWT";

    JwtPayload payload = {};
    payload.sub = "John";
    payload.iss = "wso2";
    payload.jti = "100078234ba23";
    payload.aud = ["ballerina"];
    payload.exp = time:currentTime().time/1000 + 600;

    var results = issueJwt(jwtHeader, payload, config);
    if (results is string) {
        string[] parts = stringutils:split(results, "\\.");

        // check header
        var headerDecodedResults = encoding:decodeBase64Url(parts[0]);
        if (headerDecodedResults is byte[]) {
            var resultsHeader = str:fromBytes(headerDecodedResults);
            if (resultsHeader is string) {
                test:assertEquals("{\"alg\":\"RS256\", \"typ\":\"JWT\"}", resultsHeader, msg = "Found unexpected header");
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }

        // check payload
        var payloadDecodedResults = encoding:decodeBase64Url(parts[1]);
        if (payloadDecodedResults is byte[]) {
            var resultsPayload = str:fromBytes(payloadDecodedResults);
            if (resultsPayload is string) {
                test:assertTrue(resultsPayload.startsWith("{\"sub\":\"John\", \"iss\":\"wso2\", \""));
                test:assertTrue(resultsPayload.endsWith("\", \"aud\":[\"ballerina\"]}"));
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }
    } else {
        string? errMsg = results.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testIssueJwtWithSingleAudAndAudAsArray"]
}
function testIssueJwtWithNoIssOrSub() {
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig config = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };

    JwtHeader jwtHeader = {};
    jwtHeader.alg = RS256;
    jwtHeader.typ = "JWT";

    JwtPayload payload = {};
    payload.jti = "100078234ba23";
    payload.aud = ["ballerina", "ballerinaSamples"];
    payload.exp = time:currentTime().time/1000 + 600;

    var results = issueJwt(jwtHeader, payload, config);
    if (results is string) {
        string[] parts = stringutils:split(results, "\\.");

        // check header
        var headerDecodedResults = encoding:decodeBase64Url(parts[0]);
        if (headerDecodedResults is byte[]) {
            var resultsHeader = str:fromBytes(headerDecodedResults);
            if (resultsHeader is string) {
                test:assertEquals("{\"alg\":\"RS256\", \"typ\":\"JWT\"}", resultsHeader, msg = "Found unexpected header");
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }

        // check payload
        var payloadDecodedResults = encoding:decodeBase64Url(parts[1]);
        if (payloadDecodedResults is byte[]) {
            var resultsPayload = str:fromBytes(payloadDecodedResults);
            if (resultsPayload is string) {
                test:assertTrue(resultsPayload.startsWith("{\"exp\":"));
                test:assertTrue(resultsPayload.endsWith("\", \"aud\":[\"ballerina\", \"ballerinaSamples\"]}"));
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }
    } else {
        string? errMsg = results.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testIssueJwtWithNoIssOrSub"]
}
function testIssueJwtWithNoAudOrSub() {
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig config = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };

    JwtHeader jwtHeader = {};
    jwtHeader.alg = RS256;
    jwtHeader.typ = "JWT";

    JwtPayload payload = {};
    payload.sub = "John";
    payload.iss = "wso2";
    payload.jti = "100078234ba23";
    payload.exp = time:currentTime().time/1000 + 600;

    var results = issueJwt(jwtHeader, payload, config);
    if (results is string) {
        string[] parts = stringutils:split(results, "\\.");

        // check header
        var headerDecodedResults = encoding:decodeBase64Url(parts[0]);
        if (headerDecodedResults is byte[]) {
            var resultsHeader = str:fromBytes(headerDecodedResults);
            if (resultsHeader is string) {
                test:assertEquals("{\"alg\":\"RS256\", \"typ\":\"JWT\"}", resultsHeader, msg = "Found unexpected header");
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }

        // check payload
        var payloadDecodedResults = encoding:decodeBase64Url(parts[1]);
        if (payloadDecodedResults is byte[]) {
            var resultsPayload = str:fromBytes(payloadDecodedResults);
            if (resultsPayload is string) {
                test:assertTrue(resultsPayload.startsWith("{\"sub\":\"John\", \"iss\":\"wso2\", \"exp\":"));
                test:assertTrue(resultsPayload.endsWith("\"}"));
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }
    } else {
        string? errMsg = results.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testIssueJwtWithNoAudOrSub"]
}
function testIssueJwtWithCustomClaims() {
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig config = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };

    JwtHeader jwtHeader = {};
    jwtHeader.alg = RS256;
    jwtHeader.typ = "JWT";

    JwtPayload payload = {};
    payload.sub = "John";
    payload.iss = "wso2";
    payload.jti = "100078234ba23";
    payload.aud = ["ballerina", "ballerinaSamples"];
    payload.exp = time:currentTime().time/1000 + 600;
    payload.customClaims = { "scope": "test-scope" };

    var results = issueJwt(jwtHeader, payload, config);
    if (results is string) {
        string[] parts = stringutils:split(results, "\\.");

        // check header
        var headerDecodedResults = encoding:decodeBase64Url(parts[0]);
        if (headerDecodedResults is byte[]) {
            var resultsHeader = str:fromBytes(headerDecodedResults);
            if (resultsHeader is string) {
                test:assertEquals("{\"alg\":\"RS256\", \"typ\":\"JWT\"}", resultsHeader, msg = "Found unexpected header");
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }

        // check payload
        var payloadDecodedResults = encoding:decodeBase64Url(parts[1]);
        if (payloadDecodedResults is byte[]) {
            var resultsPayload = str:fromBytes(payloadDecodedResults);
            if (resultsPayload is string) {
                test:assertTrue(resultsPayload.startsWith("{\"sub\":\"John\", \"iss\":\"wso2\", \""));
                test:assertTrue(resultsPayload.endsWith("\", \"aud\":[\"ballerina\", \"ballerinaSamples\"], \"scope\":\"test-scope\"}"));
            } else {
                test:assertFail(msg = "Expected string, but found error");
            }
        } else {
            test:assertFail(msg = "Expected byte[], but found error");
        }
    } else {
        string? errMsg = results.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testIssueJwtWithCustomClaims"]
}
function testValidateJwt() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig config = {
        issuer: "wso2",
        audience: ["ballerina", "ballerinaSamples"],
        clockSkewInSeconds: 60,
        signatureConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };

    var result = validateJwt(jwt2, config);
    if !(result is JwtPayload) {
        string? errMsg = result.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT");
    }
}

@test:Config {
    dependsOn: ["testValidateJwt"]
}
function testValidateJwtWithSingleAud() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig config = {
        issuer: "wso2",
        audience: "ballerina",
        clockSkewInSeconds: 60,
        signatureConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };

    var result = validateJwt(jwt2, config);
    if !(result is JwtPayload) {
        string? errMsg = result.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT");
    }
}

@test:Config {
    dependsOn: ["testValidateJwtWithSingleAud"]
}
function testValidateJwtWithSingleAudAndAudAsArray() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig config = {
        issuer: "wso2",
        audience: "ballerina",
        clockSkewInSeconds: 60,
        signatureConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };

    var result = validateJwt(jwt2, config);
    if !(result is JwtPayload) {
        string? errMsg = result.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT");
    }
}

@test:Config {
    dependsOn: ["testValidateJwtWithSingleAudAndAudAsArray"]
}
function testValidateJwtWithNoIssOrSub() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig config = {
        audience: "ballerinaSamples",
        clockSkewInSeconds: 60,
        signatureConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };

    var result = validateJwt(jwt2, config);
    if !(result is JwtPayload) {
        string? errMsg = result.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT");
    }
}

@test:Config {
    dependsOn: ["testValidateJwtWithNoIssOrSub"]
}
function testValidateJwtWithInvalidSignature() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig config = {
        signatureConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };

    var result = validateJwt(jwt2, config);
    if !(result is JwtPayload) {
        string? errMsg = result.detail()?.message;
        test:assertFail(msg = errMsg is string ? errMsg : "Error in validating JWT");
    }
}
