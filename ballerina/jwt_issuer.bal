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
import ballerina/time;

# Represents JWT issuer configurations.
#
# + issuer - JWT issuer, which is mapped to the `iss`
# + username - JWT username, which is mapped to the `sub`
# + audience - JWT audience, which is mapped to the `aud`
# + jwtId - JWT ID, which is mapped to the `jti`
# + keyId - JWT key ID, which is mapped the `kid`
# + customClaims - Map of custom claims
# + expTime - Expiry time in seconds
# + signatureConfig - JWT signature configurations
public type IssuerConfig record {|
    string issuer?;
    string username?;
    string|string[] audience?;
    string jwtId?;
    string keyId?;
    map<json> customClaims?;
    decimal expTime = 300;
    IssuerSignatureConfig signatureConfig?;
|};

# Represents JWT signature configurations.
#
# + algorithm - Cryptographic signing algorithm for JWS
# + config - KeyStore configurations, private key configurations, `crypto:PrivateKey` or shared key configurations
public type IssuerSignatureConfig record {|
    SigningAlgorithm algorithm = RS256;
    record {|
        crypto:KeyStore keyStore;
        string keyAlias;
        string keyPassword;
    |} | record {|
        string keyFile;
        string keyPassword?;
    |} | crypto:PrivateKey | string config?;
|};

# Issues a JWT based on the provided configurations. JWT will be signed (JWS) if `crypto:KeyStore` information is
# provided in the `jwt:KeyStoreConfig` and the `jwt:SigningAlgorithm` is not `jwt:NONE`.
# ```ballerina
# string jwt = check jwt:issue(issuerConfig);
# ```
#
# + issuerConfig - JWT issuer configurations
# + return - JWT as a `string` or else a `jwt:Error` if an error occurred
public isolated function issue(IssuerConfig issuerConfig) returns string|Error {
    Header header = prepareHeader(issuerConfig);
    Payload payload = preparePayload(issuerConfig);
    string headerString = check buildHeaderString(header);
    string payloadString = check buildPayloadString(payload);
    string jwtAssertion = headerString + "." + payloadString;

    IssuerSignatureConfig? issuerSignatureConfig = issuerConfig?.signatureConfig;
    if issuerSignatureConfig is () {
        return jwtAssertion;
    }
    IssuerSignatureConfig signatureConfig = <IssuerSignatureConfig>issuerSignatureConfig;
    SigningAlgorithm algorithm = signatureConfig.algorithm;
    if algorithm is NONE {
        return jwtAssertion;
    }
    var config = signatureConfig?.config;
    if config is () {
        return prepareError("Signing JWT requires keystore information or private key information.");
    } else if config is string {
        return hmacJwtAssertion(jwtAssertion, algorithm, config);
    } else if config?.keyStore is crypto:KeyStore {
        crypto:KeyStore keyStore = <crypto:KeyStore> config?.keyStore;
        string keyAlias = <string> config?.keyAlias;
        string keyPassword = <string> config?.keyPassword;
        crypto:PrivateKey|crypto:Error privateKey = crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, keyAlias, keyPassword);
        if privateKey is crypto:PrivateKey {
            return signJwtAssertion(jwtAssertion, algorithm, privateKey);
        } else {
            return prepareError("Failed to decode private key.", privateKey);
        }
    } else if config is crypto:PrivateKey {
        return signJwtAssertion(jwtAssertion, algorithm, config);
    } else {
        string keyFile = <string> config?.keyFile;
        string? keyPassword = config?.keyPassword;
        crypto:PrivateKey|crypto:Error privateKey = crypto:decodeRsaPrivateKeyFromKeyFile(keyFile, keyPassword);
        if privateKey is crypto:PrivateKey {
            return signJwtAssertion(jwtAssertion, algorithm, privateKey);
        } else {
            return prepareError("Failed to decode private key.", privateKey);
        }
    }
}

isolated function signJwtAssertion(string jwtAssertion, SigningAlgorithm alg, crypto:PrivateKey privateKey)
                                   returns string|Error {
    match alg {
        RS256 => {
            byte[]|crypto:Error signature = crypto:signRsaSha256(jwtAssertion.toBytes(), privateKey);
            if signature is byte[] {
                return (jwtAssertion + "." + encodeBase64Url(signature));
            } else {
                return prepareError("RSA private key signing failed for SHA256 algorithm.", signature);
            }
        }
        RS384 => {
            byte[]|crypto:Error signature = crypto:signRsaSha384(jwtAssertion.toBytes(), privateKey);
            if signature is byte[] {
                return (jwtAssertion + "." + encodeBase64Url(signature));
            } else {
                return prepareError("RSA private key signing failed for SHA384 algorithm.", signature);
            }
        }
        RS512 => {
            byte[]|crypto:Error signature = crypto:signRsaSha512(jwtAssertion.toBytes(), privateKey);
            if signature is byte[] {
                return (jwtAssertion + "." + encodeBase64Url(signature));
            } else {
                return prepareError("RSA private key signing failed for SHA512 algorithm.", signature);
            }
        }
        _ => {
            return prepareError("Unsupported signing algorithm '" + alg.toString() + "'.");
        }
    }
}

isolated function hmacJwtAssertion(string jwtAssertion, SigningAlgorithm alg, string secret)
                                   returns string|Error {
    match alg {
        HS256 => {
            byte[]|crypto:Error signature = crypto:hmacSha256(jwtAssertion.toBytes(), secret.toBytes());
            if signature is byte[] {
                return (jwtAssertion + "." + encodeBase64Url(signature));
            } else {
                return prepareError("HMAC secret key signing failed for SHA256 algorithm.", signature);
            }
        }
        HS384 => {
            byte[]|crypto:Error signature = crypto:hmacSha384(jwtAssertion.toBytes(), secret.toBytes());
            if signature is byte[] {
                return (jwtAssertion + "." + encodeBase64Url(signature));
            } else {
                return prepareError("HMAC secret key signing failed for SHA384 algorithm.", signature);
            }
        }
        HS512 => {
            byte[]|crypto:Error signature = crypto:hmacSha512(jwtAssertion.toBytes(), secret.toBytes());
            if signature is byte[] {
                return (jwtAssertion + "." + encodeBase64Url(signature));
            } else {
                return prepareError("HMAC secret key signing failed for SHA512 algorithm.", signature);
            }
        }
        _ => {
            return prepareError("Unsupported signing algorithm '" + alg.toString() + "'.");
        }
    }
}

isolated function prepareHeader(IssuerConfig issuerConfig) returns Header {
    Header header = { alg: NONE, typ: "JWT" };
    IssuerSignatureConfig? issuerSignatureConfig = issuerConfig?.signatureConfig;
    if issuerSignatureConfig is IssuerSignatureConfig {
        header.alg = issuerSignatureConfig.algorithm;
    }
    string? kid = issuerConfig?.keyId;
    if kid is string {
        header.kid = kid;
    }
    return header;
}

isolated function preparePayload(IssuerConfig issuerConfig) returns Payload {
    [int, decimal] currentTime = time:utcNow();
    Payload payload = {
        exp: currentTime[0] + <int> issuerConfig.expTime,
        iat: currentTime[0],
        nbf: currentTime[0]
    };

    string? iss = issuerConfig?.issuer;
    if iss is string {
        payload.iss = iss;
    }
    string? sub = issuerConfig?.username;
    if sub is string {
        payload.sub = sub;
    }
    string|string[]? aud = issuerConfig?.audience;
    if aud is string || aud is string[] {
        payload.aud = aud;
    }
    string? jti = issuerConfig?.jwtId;
    if jti is string {
        payload.jti = jti;
    }

    map<json>? customClaims = issuerConfig?.customClaims;
    if customClaims is map<json> {
        foreach string key in customClaims.keys() {
            payload[key] = customClaims[key];
        }
    }
    return payload;
}

isolated function buildHeaderString(Header header) returns string|Error {
    if !validateMandatoryHeaderFields(header) {
        return prepareError("Mandatory field signing algorithm (alg) is empty.");
    }
    return encodeBase64Url(header.toJsonString().toBytes());
}

isolated function buildPayloadString(Payload payload) returns string|Error {
    return encodeBase64Url(payload.toJsonString().toBytes());
}
