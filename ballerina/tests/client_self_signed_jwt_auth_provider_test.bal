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
isolated function testClientJwtAuthProviderSuccess() {
    IssuerConfig jwtConfig = {
        username: "admin",
        issuer: "wso2",
        audience: ["ballerina"],
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
    ClientSelfSignedJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    string|Error result = jwtAuthProvider.generateToken();
    if (result is string) {
        test:assertTrue(result.startsWith("eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QifQ"));
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Test Failed!");
    }
}
