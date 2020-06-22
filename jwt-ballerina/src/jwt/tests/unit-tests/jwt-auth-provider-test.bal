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
import ballerina/test;

string jwt1 = "";
string jwt2 = "";

@test:Config {
}
function testGenerateJwt() {
    JwtHeader header = {
        alg: "RS256",
        typ: "JWT"
    };
    JwtPayload payload = {
        iss: "wso2",
        sub: "John",
        aud: "ballerina",
        exp: 32475251189000
    };
    crypto:KeyStore keyStore = { path: KEYSTORE_PATH, password: "ballerina" };
    JwtKeyStoreConfig keyStoreConfig = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };
    var results = issueJwt(header, payload, keyStoreConfig);
    if (results is string) {
        jwt1 = results;
        test:assertTrue(results.startsWith("eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QifQ.eyJzdWIiOiJKb2huIiwgImlzcyI6IndzbzIiLCAiZXhwIjozMjQ3NTI1MTE4OTAwMCwgImF1ZCI6ImJhbGxlcmluYSJ9."));
    } else {
        string? errMsg = results.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testGenerateJwt"]
}
function testVerifyJwt() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: "ballerina",
        clockSkewInSeconds: 0,
        trustStoreConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };
    var results = validateJwt(jwt1, validatorConfig);
    if !(results is JwtPayload) {
        string? errMsg = results.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in generated JWT");
    }
}

@test:Config {
    dependsOn: ["testGenerateJwt"]
}
function testJwtAuthProviderAuthenticationSuccess() {
    crypto:TrustStore trustStore = { path: TRUSTSTORE_PATH, password: "ballerina" };
    JwtValidatorConfig jwtConfig = {
        issuer: "wso2",
        audience: "ballerina",
        trustStoreConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };
    InboundJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    var results = jwtAuthProvider.authenticate(jwt1);
    if (results is boolean) {
        test:assertTrue(results);
    } else {
        string? errMsg = results.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Error in JWT authentication");
    }
}

function generateJwt(string keyStorePath) returns string|Error {
    JwtHeader header = {
        alg: "RS256",
        typ: "JWT"
    };
    JwtPayload payload = {
        iss: "wso2",
        sub: "John",
        aud: "ballerina",
        exp: 32475251189000
    };
    crypto:KeyStore keyStore = { path: keyStorePath, password: "ballerina" };
    JwtKeyStoreConfig keyStoreConfig = {
        keyStore: keyStore,
        keyAlias: "ballerina",
        keyPassword: "ballerina"
    };
    return issueJwt(header, payload, keyStoreConfig);
}

function verifyJwt(string jwt, string trustStorePath) returns @tainted (JwtPayload|Error) {
    crypto:TrustStore trustStore = { path: trustStorePath, password: "ballerina" };
    JwtValidatorConfig validatorConfig = {
        issuer: "wso2",
        audience: "ballerina",
        clockSkewInSeconds: 0,
        trustStoreConfig: {
            trustStore: trustStore,
            certificateAlias: "ballerina"
        }
    };
    return validateJwt(jwt, validatorConfig);
}
