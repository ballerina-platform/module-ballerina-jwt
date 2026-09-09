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

// An hour of skew extends the lifetime of every token the service accepts
public function inlineLargeClockSkew(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        clockSkew: 3600,
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}

// Negative case - skew that covers realistic clock drift only
public function smallClockSkew(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        clockSkew: 60,
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}

// Negative case - the default of no skew
public function defaultClockSkew(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}

// A decimal literal may spell its type out with a suffix
public function suffixedLargeClockSkew(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        clockSkew: 301d,
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}

// The skew is held in a constant
const decimal CONSTANT_SKEW_SECONDS = 3600;

public function constantLargeClockSkew(string token) returns error? {
    jwt:Payload _ = check jwt:validate(token, {
        issuer: "wso2",
        audience: "ballerina",
        clockSkew: CONSTANT_SKEW_SECONDS,
        signatureConfig: {
            certFile: "/path/to/public.crt"
        }
    });
}
