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

// A token minted for another service by the same issuer is accepted
public function withoutIssuer(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        audience: "ballerina",
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}

// The token is not checked against an intended audience
public function withoutAudience(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}

// Negative case - both the issuer and the audience are pinned
public function withIssuerAndAudience(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}
