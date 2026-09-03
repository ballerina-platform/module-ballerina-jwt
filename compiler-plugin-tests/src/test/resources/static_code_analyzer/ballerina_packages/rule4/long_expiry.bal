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

// A token that stays valid for a week cannot be withdrawn once stolen
public function inlineLongExpiry() returns error? {
    string _ = check jwt:issue({
        issuer: "wso2",
        audience: "ballerina",
        expTime: 604800,
        signatureConfig: {
            algorithm: jwt:RS256,
            config: {
                keyFile: "/path/to/private.key"
            }
        }
    });
}

// The same through a variable
jwt:IssuerConfig longLivedIssuerConfig = {
    issuer: "wso2",
    audience: "ballerina",
    expTime: 2592000,
    signatureConfig: {
        algorithm: jwt:RS256,
        config: {
            keyFile: "/path/to/private.key"
        }
    }
};

public function moduleVariableLongExpiry() returns error? {
    string _ = check jwt:issue(longLivedIssuerConfig);
}

// Negative case - a short lifetime
public function shortExpiry() returns error? {
    string _ = check jwt:issue({
        issuer: "wso2",
        audience: "ballerina",
        expTime: 300,
        signatureConfig: {
            algorithm: jwt:RS256,
            config: {
                keyFile: "/path/to/private.key"
            }
        }
    });
}
