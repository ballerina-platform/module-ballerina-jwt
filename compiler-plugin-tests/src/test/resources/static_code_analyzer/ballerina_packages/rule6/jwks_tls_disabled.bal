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

// The signing keys are fetched from any host able to answer for the JWKS URL
public function inlineDisabledJwksTls(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            jwksConfig: {
                url: "https://idp.example.com/jwks",
                clientConfig: {
                    secureSocket: {
                        disable: true
                    }
                }
            }
        }
    });
}

// Negative case - the JWKS endpoint certificate is validated
public function validatedJwksTls(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            jwksConfig: {
                url: "https://idp.example.com/jwks",
                clientConfig: {
                    secureSocket: {
                        cert: "/path/to/public.crt"
                    }
                }
            }
        }
    });
}

// The nested client configuration is held in a variable
jwt:ClientConfiguration insecureJwksClientConfig = {
    secureSocket: {
        disable: true
    }
};

public function variableJwksClientConfig(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            jwksConfig: {
                url: "https://idp.example.com/jwks",
                clientConfig: insecureJwksClientConfig
            }
        }
    });
}
