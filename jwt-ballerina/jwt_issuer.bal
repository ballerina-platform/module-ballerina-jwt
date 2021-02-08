// Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/crypto;
import ballerina/encoding;
import ballerina/time;
import ballerina/uuid;

# Represents JWT issuer configurations.
#
# + username - JWT username, which is mapped to `sub`
# + issuer - JWT issuer, which is mapped to `iss`
# + audience - JWT audience, which is mapped to `aud`
# + keyId - JWT key ID, which is mapped `kid`
# + customClaims - Map of custom claims
# + expTimeInSeconds - Expiry time in seconds
# + signingAlgorithm - Cryptographic signing algorithm for JWS
# + keyStoreConfig - JWT key store configurations
public type IssuerConfig record {|
    string username?;
    string issuer?;
    string|string[] audience?;
    string keyId?;
    map<json> customClaims?;
    int expTimeInSeconds = 300;
    SigningAlgorithm signingAlgorithm = RS256;
    KeyStoreConfig keyStoreConfig?;
|};

# Represents JWT key store configurations.
#
# + keyStore - Keystore to be used in JWS signing
# + keyAlias - Signing key alias
# + keyPassword - Signing key password
public type KeyStoreConfig record {|
    crypto:KeyStore keyStore;
    string keyAlias;
    string keyPassword;
|};

# Issues a JWT based on the provided configurations. JWT will be signed (JWS) if `crypto:KeyStore` information is
# provided in the `jwt:KeyStoreConfig` and the `jwt:SigningAlgorithm` is not `jwt:NONE`.
# ```ballerina
# string|jwt:Error jwt = jwt:issue(issuerConfig);
# ```
#
# + issuerConfig - JWT issuer configurations
# + return - JWT as a `string` or else a `jwt:Error` if token issuing fails
public isolated function issue(IssuerConfig issuerConfig) returns string|Error {
    Header header = prepareHeader(issuerConfig);
    Payload payload = preparePayload(issuerConfig);
    string headerString = check buildHeaderString(header);
    string payloadString = check buildPayloadString(payload);
    string jwtAssertion = headerString + "." + payloadString;

    SigningAlgorithm algorithm = issuerConfig.signingAlgorithm;
    KeyStoreConfig? keyStoreConfig = issuerConfig?.keyStoreConfig;
    if (algorithm is NONE) {
        return jwtAssertion;
    }
    if (keyStoreConfig is ()) {
        return prepareError("Signing JWT requires KeyStoreConfig with keystore information.");
    }
    KeyStoreConfig ksc = <KeyStoreConfig>keyStoreConfig;
    crypto:KeyStore keyStore = ksc.keyStore;
    string keyAlias = ksc.keyAlias;
    string keyPassword = ksc.keyPassword;
    crypto:PrivateKey|crypto:Error decodedResults = crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, keyAlias, keyPassword);
    if (decodedResults is crypto:Error) {
        return prepareError("Private key decoding failed.", decodedResults);
    }
    crypto:PrivateKey privateKey = checkpanic decodedResults;
    match (algorithm) {
        RS256 => {
            byte[]|crypto:Error signature = crypto:signRsaSha256(jwtAssertion.toBytes(), privateKey);
            if (signature is byte[]) {
                return (jwtAssertion + "." + encoding:encodeBase64Url(signature));
            } else {
                return prepareError("Private key signing failed for SHA256 algorithm.", signature);
            }
        }
        RS384 => {
            byte[]|crypto:Error signature = crypto:signRsaSha384(jwtAssertion.toBytes(), privateKey);
            if (signature is byte[]) {
                return (jwtAssertion + "." + encoding:encodeBase64Url(signature));
            } else {
                return prepareError("Private key signing failed for SHA384 algorithm.", signature);
            }
        }
        RS512 => {
            byte[]|crypto:Error signature = crypto:signRsaSha512(jwtAssertion.toBytes(), privateKey);
            if (signature is byte[]) {
                return (jwtAssertion + "." + encoding:encodeBase64Url(signature));
            } else {
                return prepareError("Private key signing failed for SHA512 algorithm.", signature);
            }
        }
        _ => {
            return prepareError("Unsupported JWS algorithm.");
        }
    }
}

isolated function prepareHeader(IssuerConfig issuerConfig) returns Header {
    Header header = { alg: issuerConfig.signingAlgorithm, typ: "JWT" };
    string? kid = issuerConfig?.keyId;
    if (kid is string) {
        header.kid = kid;
    }
    return header;
}

isolated function preparePayload(IssuerConfig issuerConfig) returns Payload {
    Payload payload = {
        exp: time:currentTime().time / 1000 + issuerConfig.expTimeInSeconds,
        iat: time:currentTime().time / 1000,
        nbf: time:currentTime().time / 1000,
        jti: uuid:createType4AsString()
    };

    string? sub = issuerConfig?.username;
    if (sub is string) {
        payload.sub = sub;
    }
    string? iss = issuerConfig?.issuer;
    if (iss is string) {
        payload.iss = iss;
    }
    string|string[]? aud = issuerConfig?.audience;
    if (aud is string || aud is string[]) {
        payload.aud = aud;
    }

    map<json>? customClaims = issuerConfig?.customClaims;
    if (customClaims is map<json>) {
        foreach string key in customClaims.keys() {
            payload[key] = customClaims[key].toJsonString();
        }
    }
    return payload;
}

isolated function buildHeaderString(Header header) returns string|Error {
    if (!validateMandatoryHeaderFields(header)) {
        return prepareError("Mandatory field signing algorithm (alg) is empty.");
    }
    return encoding:encodeBase64Url(header.toJsonString().toBytes());
}

isolated function buildPayloadString(Payload payload) returns string|Error {
    return encoding:encodeBase64Url(payload.toJsonString().toBytes());
}

isolated function appendToMap(map<json> fromMap, map<json> toMap) returns map<json> {
    foreach json key in fromMap.keys() {
        toMap[key] = fromMap[key];
    }
    return toMap;
}
