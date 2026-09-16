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

import ballerina/jwt as myjwt;

const NONE_ALGORITHM = "none";
const STRONG_ALGORITHM = "RS256";

// The constant reached through an import alias
public function aliasedConstantAlgorithm() returns error? {
    string _ = check myjwt:issue({
        issuer: "ballerina",
        expTime: 3600,
        signatureConfig: {
            algorithm: myjwt:NONE
        }
    });
}

// A constant of this module carrying the same value
public function localConstantAlgorithm() returns error? {
    string _ = check myjwt:issue({
        issuer: "ballerina",
        expTime: 3600,
        signatureConfig: {
            algorithm: NONE_ALGORITHM
        }
    });
}

// Negative case - a constant carrying a signing algorithm
public function strongConstantAlgorithm() returns error? {
    string _ = check myjwt:issue({
        issuer: "ballerina",
        expTime: 3600,
        signatureConfig: {
            algorithm: STRONG_ALGORITHM
        }
    });
}
