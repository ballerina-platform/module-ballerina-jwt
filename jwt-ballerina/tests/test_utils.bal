// Copyright (c) 2020 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/test;

const string KEYSTORE_PATH = "tests/resources/keystore/ballerinaKeystore.p12";
const string TRUSTSTORE_PATH = "tests/resources/keystore/ballerinaTruststore.p12";
const string PRIVATE_KEY_PATH = "tests/resources/key/private.key";
const string ENCRYPTED_PRIVATE_KEY_PATH = "tests/resources/key/encryptedPrivate.key";
const string PUBLIC_CERT_PATH = "tests/resources/cert/public.crt";
const string INVALID_PUBLIC_CERT_PATH = "tests/resources/cert/invalidPublic.crt";

// {
//  "alg": "RS256",
//  "typ": "JWT",
//  "kid": "5a0b754-895f-4279-8843-b745e11a57e9"
// }
// {
//  "iss": "wso2",
//  "sub": "John",
//  "aud": [
//    "ballerina",
//    "ballerinaSamples"
//  ],
//  "jti": "JlbmMiOiJBMTI4Q0JDLUhTMjU2In",
//  "exp": 1935400394,
//  "nbf": 1620040394,
//  "iat": 1620040394,
//  "scp": "hello"
// }
const string JWT1 = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiNWEwYjc1NC04OTVmLTQyNzktODg0My1iNzQ1ZTExYTU3ZTk" +
                    "ifQ.eyJpc3MiOiJ3c28yIiwgInN1YiI6IkpvaG4iLCAiYXVkIjpbImJhbGxlcmluYSIsICJiYWxsZXJpbmFTYW1wbGVzIl0" +
                    "sICJqdGkiOiJKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluIiwgImV4cCI6MTkzNTQwMDM5NCwgIm5iZiI6MTYyMDA0MD" +
                    "M5NCwgImlhdCI6MTYyMDA0MDM5NCwgInNjcCI6ImhlbGxvIn0.I9XAfgOkIRor-PTshCzikw92N6jNNPmwXsUTr0OI6bMmG" +
                    "oEoHw0Uo1g3zOfgKOFfIN0bVqUs9gcg05biojIqFmMErrfG4h1DIIym4PLXWzQ-JWPNnMFYSAC5C84MvBPU5kYMnNbVSTsp" +
                    "SbQXocY0FHe2_GvhdwHDviRPMS3RnkJxRVORD9BF4DLJuQJdEJUbT_iYSTCd7ay88oCEgm7KGTDKy66-JqC7FAppc7mj7Lk" +
                    "N48T26BW0aC5wN2LJkYql2H3ONewHOTuEFyH6cZl7dfm66hZiryqMK1BIMwecMscUqKof1h8cHWZ4BDeccCJ5vWNe0SHTrx" +
                    "3AWPcXnRd0Vw";

// {
//  "alg": "RS256",
//  "typ": "JWT",
//  "kid": "NTAxZmMxNDMyZDg3MTU1ZGM0MzEzODJhZWI4NDNlZDU1OGFkNjFiMQ"
// }
// {
//  "sub": "admin",
//  "iss": "ballerina",
//  "exp": 1907665746,
//  "jti": "100078234ba23",
//  "aud": [
//    "vEwzbcasJVQm1jVYHUHCjhxZ4tYa"
//  ]
// }
const string JWT2 = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k" +
                    "0TkRObFpEVTFPR0ZrTmpGaU1RIn0.eyJzdWIiOiJhZG1pbiIsICJpc3MiOiJiYWxsZXJpbmEiLCAiZXhwIjoxOTA3NjY1Nz" +
                    "Q2LCAianRpIjoiMTAwMDc4MjM0YmEyMyIsICJhdWQiOlsidkV3emJjYXNKVlFtMWpWWUhVSENqaHhaNHRZYSJdfQ.E8E7VO" +
                    "18V6MG7Ns87Y314Dqg8RYOMe0WWYlSYFhSv0mHkJQ8bSSyBJzFG0Se_7UsTWFBwzIALw6wUiP7UGraosilf8k6HGJWbTjWt" +
                    "LXfniJXx5NczikzciG8ADddksm-0AMi5uPsgAQdg7FNaH9f4vAL6SPMEYp2gN6GDnWTH7M1vnknwjOwTbQpGrPu_w2V1tbs" +
                    "BwSzof3Fk_cYrntu8D_pfsBu3eqFiJZD7AXUq8EYbgIxpSwvdi6_Rvw2_TAi46drouxXK2Jglz_HvheUVCERT15Y8JNJONJ" +
                    "PJ52MsN6t297hyFV9AmyNPzwHxxmi753TclbapDqDnVPI1tpc-Q";

// {
//  "alg": "RS384",
//  "typ": "JWT"
// }
// {
//  "iss": "wso2",
//  "sub": "John",
//  "aud": "ballerina",
//  "exp": 1935402506,
//  "nbf": 1620042506,
//  "iat": 1620042506
// }
const string JWT3 = "eyJhbGciOiJSUzM4NCIsICJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ3c28yIiwgInN1YiI6IkpvaG4iLCAiYXVkIjoiYmFsbGVy" +
                    "aW5hIiwgImV4cCI6MTkzNTQwMjU4NCwgIm5iZiI6MTYyMDA0MjU4NCwgImlhdCI6MTYyMDA0MjU4NH0.f9HjtIeprPxeYj_" +
                    "_00pUf8TSS_mlNNvzoY8V8Agg27D4YquxVIj5QwbKjSZ7sdLKC_jlVEwyX0fp_YGcSSfoE-s3T_1wY2e36vxzm35CJG8Lcs" +
                    "EHwjtMrilJ-CicHJKsz0QsPSJJTDJe490tmPMukh-z1Urm779gYnJroUzDcgEvnrsiLsJwTl7M_VmS56B-iXk7IFoId_6gX" +
                    "kq3uA9upmyzV6C5C257W_ApMw8icRR8HS19w0NAu5ws_sxkoM6H3SlFqidZgZ0UvTXnvLaQgBaV0RZX8ctzWOqj601vpVqh" +
                    "qGUvTNGFnpd5ZugLKJ1XXs66ZWdfTkYi2NH_-8cK8Q";

// {
//  "alg": "RS512",
//  "typ": "JWT"
// }
// {
//  "iss": "wso2",
//  "sub": "John",
//  "aud": "ballerina",
//  "exp": 1935402506,
//  "nbf": 1620042506,
//  "iat": 1620042506
// }
const string JWT4 = "eyJhbGciOiJSUzUxMiIsICJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ3c28yIiwgInN1YiI6IkpvaG4iLCAiYXVkIjoiYmFsbGVy" +
                    "aW5hIiwgImV4cCI6MTkzNTQwMjUwNiwgIm5iZiI6MTYyMDA0MjUwNiwgImlhdCI6MTYyMDA0MjUwNn0.R6SobPWHg4z8vY4" +
                    "OV8MRNocIbQV3tHrgD9MzJeuifofsCRMLAhjhKtldShxA9BnRegmawV6Hqn0dBHgrEW69ydx-frE3k8-u9LufH82Lb5JKb5" +
                    "ZUm5Zme5PVru628py_e1TGqKyDjMLRwEZUYYxIMV5nmDO6705XDH2sxRSgGBXkJxMGoycnj1UYRLvU7q315js6DKvXY7Yfa" +
                    "VvO0_xTlFs4381lTXRjkK2G1XMjZQQZK7Px4qSBLqvr9uVPHbezlVKwQs4b1jIgwsE4Fx-bjti6tWCV4NhcU4WhoYB8pYkv" +
                    "f4WrBpKhcaZQeAiCUA6bUsqSkewvDwtjL9mUs0OkCw";

// {
//  "alg": "RS256",
//  "typ": "JWT",
//  "kid": "5a0b754-895f-4279-8843-b745e11a57e9"
// }
// {
//  "iss": "wso2",
//  "sub": "John",
//  "aud": [
//    "ballerina",
//    "ballerinaSamples"
//  ],
//  "jti": "JlbmMiOiJBMTI4Q0JDLUhTMjU2In",
//  "exp": 1940845451,
//  "nbf": 1625485451,
//  "iat": 1625485451,
//  "scp": "hello"
// }
const string JWT5 = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiNWEwYjc1NC04OTVmLTQyNzktODg0My1iNzQ1ZTExYTU3ZTk" +
                    "ifQ.eyJpc3MiOiJ3c28yIiwgInN1YiI6IkpvaG4iLCAiYXVkIjpbImJhbGxlcmluYSIsICJiYWxsZXJpbmFTYW1wbGVzIl0" +
                    "sICJqdGkiOiJKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluIiwgImV4cCI6MTk0MDg0NTQ1MSwgIm5iZiI6MTYyNTQ4NT" +
                    "Q1MSwgImlhdCI6MTYyNTQ4NTQ1MSwgInNjcCI6ImhlbGxvIn0.G0c9t9AE7BmYhKCNY4DsYmypk4XDQ-lNqpENYUouugWXn" +
                    "t3-d2rpLHxnXNqcIqPBWRV6QuxO-0jcp6LjkjO2khgZ5jMVNFtlyUN4cQ9UEHfwiPAjSlkwT7sAEHPUd8S8wp714eWtkdjo" +
                    "ysgpcdEE3VJi1OgI1SeVDiN6l7jkt-xxhMsbHGYIeTc1lTLgwNtCJaNJKHvi0uJu5x9YfUznett8Dw465DbADhBLMoSBYAT" +
                    "t4flzCBsTGWC7XZaFnwT4mUlX7WpTOgv1Nsq5GVLszvsnzs6BE__Mvr4zl5pdChVbkMXX3US6fYguK268XKjzgtpMVxUpL3" +
                    "CrzwQpIRyI-Q";

// Builds the complete error message by evaluating all the inner causes and asserts the inclusion.
isolated function assertContains(error err, string text) {
    string message = err.message();
    error? cause = err.cause();
    while (cause is error) {
        message += " " + cause.message();
        cause = cause.cause();
    }
    test:assertTrue(message.includes(text));
}
