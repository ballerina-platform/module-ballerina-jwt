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

@test:Config {
    enable: false
}
public function testAuthenticationSuccess() {
    http:Client clientEP = new("https://localhost:20114", {
        secureSocket: {
            trustStore: {
                path: TRUSTSTORE_PATH,
                password: "ballerina"
            }
        }
    });

    // JWT used in the test:
    // {
    //   "x5t": "NTAxZmMxNDMyZDg3MTU1ZGM0MzEzODJhZWI4NDNlZDU1OGFkNjFiMQ",
    //   "kid": "NTAxZmMxNDMyZDg3MTU1ZGM0MzEzODJhZWI4NDNlZDU1OGFkNjFiMQ",
    //   "alg": "RS256"
    // }
    // {
    //   "sub": "admin@carbon.super",
    //   "aud": "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
    //   "nbf": 1587621890,
    //   "azp": "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
    //   "iss": "https://localhost:9443/oauth2/token",
    //   "exp": 4741221890,
    //   "iat": 1587621890,
    //   "jti": "abeae222-eb77-4862-916d-34622d4e4afc"
    // }
    http:Request req = new;
    req.setHeader("Authorization", "Bearer eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU" +
               "9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEi" +
               "LCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbkBjYXJib24uc3VwZXIiLCJhdWQiOiJ2RXd6YmNhc0pWUW0xalZZSFVIQ2poe" +
               "Fo0dFlhIiwibmJmIjoxNTg3NjIxODkwLCJhenAiOiJ2RXd6YmNhc0pWUW0xalZZSFVIQ2poeFo0dFlhIiwiaXNzIjoiaHR0cHM" +
               "6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rva2VuIiwiZXhwIjo0NzQxMjIxODkwLCJpYXQiOjE1ODc2MjE4OTAsImp0a" +
               "SI6ImFiZWFlMjIyLWViNzctNDg2Mi05MTZkLTM0NjIyZDRlNGFmYyJ9.IoD0-39h7vEAoDdnKBRtWC6tpTyADsGyXomHbsCj_o" +
               "R5B8lj7jVUG2TCKoMXD_S_BV3F3ep7zENOW8wu0M7F27yJsgas5-vJ7BO1IMLD82PReeb160CnJ2tUFrmdT1Gc7uNfXfXuJv7q" +
               "wkgaWR0VvFCfsvl88UQXyXA0rEmNYT4p_jFjKovgPsPePl6Qf0uwO--xEhGEM4cUuBog2bgY54vaLg9iHnNb6ZZ_EZvjwIONZs" +
               "eBOiB5IXDzffUXnPfwUsGaygHqw71byV61VQhDLFDsm7Jrqe3cpd8hThAUHhVkgsz3irwXPolOdlMheslOIMunVcnQLT6yvGls" +
               "rHxS0g");
    var response = clientEP->get("/echo/test", req);
    if (response is http:Response) {
        assertOK(response);
    } else {
        test:assertFail(msg = "Test Failed! " + <string>response.detail()?.message);
    }
}

@test:Config {
    enable: false
}
public function testAuthenticationFailure() {
    http:Client clientEP = new("https://localhost:20114", {
        secureSocket: {
            trustStore: {
                path: TRUSTSTORE_PATH,
                password: "ballerina"
            }
        }
    });

    // JWT used in the test:
    // {
    //   "x5t": "NTAxZmMxNDMyZDg3MTU1ZGM0MzEzODJhZWI4NDNlZDU1OGFkNjFiMQ",
    //   "kid": "<invalid-kid>",
    //   "alg": "RS256"
    // }
    // {
    //   "sub": "admin@carbon.super",
    //   "aud": "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
    //   "nbf": 1587621890,
    //   "azp": "vEwzbcasJVQm1jVYHUHCjhxZ4tYa",
    //   "iss": "https://localhost:9443/oauth2/token",
    //   "exp": 4741221890,
    //   "iat": 1587621890,
    //   "jti": "abeae222-eb77-4862-916d-34622d4e4afc"
    // }
    http:Request req = new;
    req.setHeader("Authorization", "Bearer ewogICJ4NXQiOiAiTlRBeFptTXhORE15WkRnM01UVTFaR00wTXpFek9ESmhaV0k0TkRObF" +
               "pEVTFPR0ZrTmpGaU1RIiwKICAia2lkIjogImludmFsaWQta2lkIiwKICAiYWxnIjogIlJTMjU2Igp9.eyJzdWIiOiJhZG1pbkB" +
               "jYXJib24uc3VwZXIiLCJhdWQiOiJ2RXd6YmNhc0pWUW0xalZZSFVIQ2poeFo0dFlhIiwibmJmIjoxNTg3NjIxODkwLCJhenAiO" +
               "iJ2RXd6YmNhc0pWUW0xalZZSFVIQ2poeFo0dFlhIiwiaXNzIjoiaHR0cHM6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3R" +
               "va2VuIiwiZXhwIjo0NzQxMjIxODkwLCJpYXQiOjE1ODc2MjE4OTAsImp0aSI6ImFiZWFlMjIyLWViNzctNDg2Mi05MTZkLTM0N" +
               "jIyZDRlNGFmYyJ9.IoD0-39h7vEAoDdnKBRtWC6tpTyADsGyXomHbsCj_oR5B8lj7jVUG2TCKoMXD_S_BV3F3ep7zENOW8wu0M" +
               "7F27yJsgas5-vJ7BO1IMLD82PReeb160CnJ2tUFrmdT1Gc7uNfXfXuJv7qwkgaWR0VvFCfsvl88UQXyXA0rEmNYT4p_jFjKovg" +
               "PsPePl6Qf0uwO--xEhGEM4cUuBog2bgY54vaLg9iHnNb6ZZ_EZvjwIONZseBOiB5IXDzffUXnPfwUsGaygHqw71byV61VQhDLF" +
               "Dsm7Jrqe3cpd8hThAUHhVkgsz3irwXPolOdlMheslOIMunVcnQLT6yvGlsrHxS0g");
    var response = clientEP->get("/echo/test", req);
    if (response is http:Response) {
        assertUnauthorized(response);
    } else {
        test:assertFail(msg = "Test Failed! " + <string>response.detail()?.message);
    }
}
