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

import ballerina/http;

listener http:Listener sts = new(9445,
    secureSocket = {
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        }
    }
);

service /oauth2 on sts {

    // This JWKs endpoint respond with a JSON object that represents a set of JWKs.
    // https://tools.ietf.org/html/rfc7517#section-5
    resource function get jwks() returns json {
        return {
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "use": "enc",
                "kid": "1"
            },
            {
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256",
                "kid": "2011-04-29"
            },
            {
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "kid": "NTAxZmMxNDMyZDg3MTU1ZGM0MzEzODJhZWI4NDNlZDU1OGFkNjFiMQ",
                "alg": "RS256",
                "n": "AIFcoun1YlS4mShJ8OfcczYtZXGIes_XWZ7oPhfYCqhSIJnXD3vqrUu4GXNY2E41jAm8dd7BS5GajR3g1GnaZrSqN0w3bjpdbKjOnM98l2-i9-JP5XoedJsyDzZmml8Xd7zkKCuDqZIDtZ99poevrZKd7Gx5n2Kg0K5FStbZmDbTyX30gi0_griIZyVCXKOzdLp2sfskmTeu_wF_vrCaagIQCGSc60Yurnjd0RQiMWA10jL8axJjnZ-IDgtKNQK_buQafTedrKqhmzdceozSot231I9dth7uXvmPSjpn23IYUIpdj_NXCIt9FSoMg5-Q3lhLg6GK3nZOPuqgGa8TMPs="
            }]
        };
    }
}
