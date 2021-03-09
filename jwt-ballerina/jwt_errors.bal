// Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/log;

# Represents the JWT error. This will be returned if an error occurred while issuing/validating a JWT or any operation
# related to JWT.
public type Error distinct error;

// Logs and prepares the `error` as an `jwt:Error`.
isolated function prepareError(string message, error? err = ()) returns Error {
    log:printError(message, 'error = err);
    if (err is error) {
        return error Error(message, err);
    }
    return error Error(message);
}
