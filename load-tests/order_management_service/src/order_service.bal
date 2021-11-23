// Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/cache;
import ballerina/http;

final http:JwtValidatorConfig config = {
    issuer: "wso2",
    audience: "ballerina",
    signatureConfig: {
        jwksConfig: {
            url: "https://localhost:9445/oauth2/jwks",
            clientConfig: {
                secureSocket: {
                    cert: "./resources/order_service/public.crt"
                }
            },
            cacheConfig: {
                capacity: 10,
                evictionFactor: 0.25,
                evictionPolicy: cache:LRU,
                defaultMaxAge: -1
            }
        }
    },
    cacheConfig: {
        capacity: 10,
        evictionFactor: 0.25,
        evictionPolicy: cache:LRU,
        defaultMaxAge: -1
    }
};

listener http:Listener orderEP = new (9090,
    secureSocket = {
        key: {
            certFile: "./resources/order_service/public.crt",
            keyFile: "./resources/order_service/private.key"
        }
    }
);

isolated service /'order on orderEP {

    @http:ResourceConfig {
        auth: [
            {
                jwtValidatorConfig: config,
                scopes: "add_order"
            }
        ]
    }
    isolated resource function post .(@http:Payload json payload) returns json {
        return payload;
    }
}
