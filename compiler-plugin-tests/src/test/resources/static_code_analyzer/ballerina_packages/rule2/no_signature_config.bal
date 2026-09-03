// Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/jwt;

// No signature configuration, so a self-signed token is accepted
public function inlineWithoutSignatureConfig(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina"
    });
}

// The same through a variable
jwt:ValidatorConfig unsignedValidatorConfig = {
    issuer: "wso2",
    audience: "ballerina"
};

public function moduleVariableWithoutSignatureConfig(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, unsignedValidatorConfig);
}

// Negative case - the signature is verified against a trusted certificate
public function withSignatureConfig(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}
