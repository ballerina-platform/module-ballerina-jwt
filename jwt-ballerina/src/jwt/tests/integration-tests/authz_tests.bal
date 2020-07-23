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

import ballerina/http;
import ballerina/test;

@test:Config {}
public function testAuthCache() {
    http:Client clientEP = new("https://localhost:20101", {
        secureSocket: {
            trustStore: {
                path: TRUSTSTORE_PATH,
                password: "ballerina"
            }
        }
    });

    // JWT used in the initial request:
    // {
    //   "sub": "ballerina",
    //   "iss": "ballerina",
    //   "exp": 2818415019,
    //   "iat": 1524575019,
    //   "jti": "f5aded50585c46f2b8ca233d0c2a3c9d",
    //   "aud": [
    //     "ballerina",
    //     "ballerina.org",
    //     "ballerina.io"
    //   ],
    //   "scope": "test-scope"
    // }
    http:Request req = new;
    req.setHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiYWxsZXJpbmEiLCJpc3MiO" +
               "iJiYWxsZXJpbmEiLCJleHAiOjI4MTg0MTUwMTksImlhdCI6MTUyNDU3NTAxOSwianRpIjoiZjVhZGVkNTA1ODVjNDZmMmI4Y2E" +
               "yMzNkMGMyYTNjOWQiLCJhdWQiOlsiYmFsbGVyaW5hIiwiYmFsbGVyaW5hLm9yZyIsImJhbGxlcmluYS5pbyJdLCJzY29wZSI6I" +
               "nRlc3Qtc2NvcGUifQ.UHGtfDbR4BS7qyDn2V0R5bzGH7SjLeI0MyhcTA3eyUQRG5wfajH51T0lrTV2jfD0-_92Pn1D4RDKFTIa" +
               "l2aawDBFag_4GJhRd__AxjZemCqAdKs-cqX-JNSWnB8m7cBfA9LOH-y2dmowNqv4VeMuuxKriMe9w-7YpnRPJrs-HIxLMgOdJa" +
               "YsFHEPL1wWDvlpt53wDjCveYw4OgD39S5g-pcemGUflVUMoKB3nti1qjzcIb6nDKdqQiAbnSN2UKEVLXQpZX5WUKe5SuFlKnS9" +
               "z1BbKC2z79eMe15yx8asas3krgJyKVNISUWlgPWvKHxyfh_RoQYgWPn-rhng1_P8Ag");
    var response = clientEP->get("/echo/test", req);
    if (response is http:Response) {
        assertOK(response);
    } else {
        test:assertFail(msg = "Test Failed! " + <string>response.message());
    }

    // JWT used in the second request:
    // {
    //   "sub": "ballerina",
    //   "iss": "ballerina",
    //   "exp": 2818415019,
    //   "iat": 1524575019,
    //   "jti": "f5aded50585c46f2b8ca233d0c2a3c9d",
    //   "aud": [
    //     "ballerina",
    //     "ballerina.org",
    //     "ballerina.io"
    //   ],
    //   "scope": "invalid-scope"
    // }
    req = new;
    req.setHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiYWxsZXJpbmEiLCJpc3Mi" +
               "OiJiYWxsZXJpbmEiLCJleHAiOjI4MTg0MTUwMTksImlhdCI6MTUyNDU3NTAxOSwianRpIjoiZjVhZGVkNTA1ODVjNDZmMmI4Y" +
               "2EyMzNkMGMyYTNjOWQiLCJhdWQiOlsiYmFsbGVyaW5hIiwiYmFsbGVyaW5hLm9yZyIsImJhbGxlcmluYS5pbyJdLCJzY29wZS" +
               "I6ImludmFsaWQtc2NvcGUifQ.U6qlFXduTPCkMVbPmhRaqWpKQ3UGf0TXW6ErmrRycW-Jy025nB5Akp9uH7e02TIfSXbSDtSH" +
               "XichRv_y7_VuY-WTm7QBtR5tqpBVAI59SezTE9NqxCIy-ol4RE7rQ7plOr2y80NNQfoWE6PCwsjFNc2v_FdXzR6ADvsnNZbRu" +
               "Z2nhnTpkDkdmgDOyonw4YZPG275ZQCRTJEjyUKnF4yEm9c2cwCtbOVzdThtzuJEmEcrRHAre7zZX857R2ZKo84TZ8Tes3maGY" +
               "dpwoUnOy9aseNB8iy0AAPQwf1MkpbgCUJFGLAWHAQsUBJXPpCPGMKVJ5CYzFiPC_bX_pUrzrXOJw");
    response = clientEP->get("/echo/test", req);
    if (response is http:Response) {
        assertForbidden(response);
    } else {
        test:assertFail(msg = "Test Failed! " + <string>response.message());
    }

    // JWT used in the third request:
    // {
    //   "sub": "ballerina",
    //   "iss": "ballerina1",
    //   "exp": 2818415019,
    //   "iat": 1524575019,
    //   "jti": "f5aded50585c46f2b8ca233d0c2a3c9d",
    //   "aud": [
    //     "ballerina",
    //     "ballerina.org",
    //     "ballerina.io"
    //   ],
    //   "scope": "test-scope"
    // }
    req = new;
    req.setHeader("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiYWxsZXJpbmEiLCJpc3MiO" +
               "iJiYWxsZXJpbmExIiwiZXhwIjoyODE4NDE1MDE5LCJpYXQiOjE1MjQ1NzUwMTksImp0aSI6ImY1YWRlZDUwNTg1YzQ2ZjJiOGN" +
               "hMjMzZDBjMmEzYzlkIiwiYXVkIjpbImJhbGxlcmluYSIsImJhbGxlcmluYS5vcmciLCJiYWxsZXJpbmEuaW8iXSwic2NvcGUiO" +
               "iJ0ZXN0LXNjb3BlIn0.YNgu3A0o1S2sDIsJMv3NlV6bD0iGIerglEAxCpAHwq8oDHJ8_AjBfaU75x_lJZIKftp2FLJM99UT1IS" +
               "eO9Kt3EIJHU4njheptz7Qfep_sEyYdq3CvQI5bKxUZw4bA-87AxTv_tFpSAbiBpGhD0rmhYAfkXF7QsWplDts_xFRhMmxHEsel" +
               "RKMg4F9-iX3HQYouJoRzyDJTETyzxC2vFE0FaCxVDrrs5B2KU3YB-etkPUWDFgzaoV13SaHxPBhj-f5arlfRaDk2XtbNnchHgs" +
               "LbLux8FaxyAglgRoDNgBgaCynbhUYAUnpr2JSx72FN8J0CJB5f31EMmmd4FukTtv-8w");
    response = clientEP->get("/echo/test", req);
    if (response is http:Response) {
        assertUnauthorized(response);
    } else {
        test:assertFail(msg = "Test Failed! " + <string>response.message());
    }
}
