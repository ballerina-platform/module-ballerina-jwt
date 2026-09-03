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

// Reads the claims without verifying the signature, so the values cannot be trusted
public function decodeToken(string token) returns error? {
    [jwt:Header, jwt:Payload] _ = check jwt:decode(token);
}

// Negative case - the token is validated before its claims are used
public function validateToken(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}
