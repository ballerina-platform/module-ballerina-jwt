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
isolated function testJwtAuthProviderAuthenticationSuccess() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QifQ.eyJzdWIiOiJKb2huIiwgImlzcyI6IndzbzIiLCAiZXhwIjoxOTIwOTQ0OTE" +
                 "yLCAiYXVkIjoiYmFsbGVyaW5hIn0.f22pKKF8kVbUq0UhCo3iqfAW_k9lTp5YolQGOHWmc9gmmbcmHEYs69jpujKAZy_41gkHD" +
                 "J4Qknu_jPNm1oZRAat8bXZ9Zynv_wFPbfVvm-im-B_waej_rtrIhGGRaaF43BLsb_9yLU897VhNNFJqJqr3KbI7pQiQFt2nJHN" +
                 "teAqTQFU3s4Iw7C2ZwGH0knP_4LgLIicR6ex3iN37dVqazgq-jb266gENSuLXDRKRcTh219dSbFRaCE9f4Ae4jbQ5w4vNUbunY" +
                 "qxJfnnJCOv95s2dR61Li08hdCFEZhwHJMKxYfUAAsR7G2mq0aOBsq1zIRo1aYgzLOCPmdLXliLCRw";
    ValidatorConfig jwtConfig = {
        issuer: "wso2",
        audience: "ballerina",
        trustStoreConfig: {
            trustStore: {
                path: TRUSTSTORE_PATH,
                password: "ballerina"
            },
            certificateAlias: "ballerina"
        }
    };
    InboundJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    Payload|Error result = jwtAuthProvider.authenticate(jwt);
    if (result is Payload) {
        test:assertEquals(result?.iss, "wso2");
        test:assertEquals(result?.aud, "ballerina");
    } else {
        string? errMsg = result.message();
        test:assertFail(msg = errMsg is string ? errMsg : "Test Failed!");
    }
}

@test:Config {}
isolated function testJwtAuthProviderAuthenticationFailure() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QifQ.eyJzdWIiOiJKb2huIiwgImlzcyI6IndzbzIiLCAiZXhwIjoxOTIwOTQ0OTE" +
                 "yLCAiYXVkIjoiYmFsbGVyaW5hIn0.f22pKKF8kVbUq0UhCo3iqfAW_k9lTp5YolQGOHWmc9gmmbcmHEYs69jpujKAZy_41gkHD" +
                 "J4Qknu_jPNm1oZRAat8bXZ9Zynv_wFPbfVvm-im-B_waej_rtrIhGGRaaF43BLsb_9yLU897VhNNFJqJqr3KbI7pQiQFt2nJHN" +
                 "teAqTQFU3s4Iw7C2ZwGH0knP_4LgLIicR6ex3iN37dVqazgq-jb266gENSuLXDRKRcTh219dSbFRaCE9f4Ae4jbQ5w4vNUbunY" +
                 "qxJfnnJCOv95s2dR61Li08hdCFEZhwHJMKxYfUAAsR7G2mq0aOBsq1zIRo1aYgzLOCPmdLXliLCRw";
    ValidatorConfig jwtConfig = {
        issuer: "invalid",
        audience: "ballerina",
        trustStoreConfig: {
            trustStore: {
                path: TRUSTSTORE_PATH,
                password: "ballerina"
            },
            certificateAlias: "ballerina"
        }
    };
    InboundJwtAuthProvider jwtAuthProvider = new(jwtConfig);
    Payload|Error result = jwtAuthProvider.authenticate(jwt);
    if (result is Error) {
        test:assertEquals(result.message(), "JWT validation failed.");
    } else {
        test:assertFail("Test Failed!");
    }
}
