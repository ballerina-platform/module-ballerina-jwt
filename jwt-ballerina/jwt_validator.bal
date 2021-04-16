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

import ballerina/cache;
import ballerina/crypto;
import ballerina/jballerina.java;
import ballerina/lang.'int;
import ballerina/lang.'string;
import ballerina/log;
import ballerina/regex;
import ballerina/time;

# Represents JWT validator configurations.
#
# + issuer - Expected issuer, which is mapped to the `iss`
# + audience - Expected audience, which is mapped to the `aud`
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + signatureConfig - JWT signature configurations
# + cacheConfig - Configurations related to the cache, which are used to store parsed JWT information
public type ValidatorConfig record {
    string issuer?;
    string|string[] audience?;
    decimal clockSkew = 0;
    ValidatorSignatureConfig signatureConfig?;
    cache:CacheConfig cacheConfig?;
};

# Represents JWT signature configurations.
#
# + jwksConfig - JWKS configurations
# + certFile - Public certificate file
# + trustStoreConfig - JWT TrustStore configurations
public type ValidatorSignatureConfig record {|
    record {|
        string url;
        cache:CacheConfig cacheConfig?;
        ClientConfiguration clientConfig = {};
    |} jwksConfig?;
    string certFile?;
    record {|
        crypto:TrustStore trustStore;
        string certAlias;
    |} trustStoreConfig?;
|};

# Represents the configurations of the client used to call the JWKS endpoint.
#
# + httpVersion - The HTTP version of the client
# + secureSocket - SSL/TLS-related configurations
public type ClientConfiguration record {|
    HttpVersion httpVersion = HTTP_1_1;
    SecureSocket secureSocket?;
|};

# Represents HTTP versions.
public enum HttpVersion {
    HTTP_1_1,
    HTTP_2
}

# Represents the SSL/TLS configurations.
#
# + disable - Disable SSL validation
# + cert - Configurations associated with the `crypto:TrustStore` or single certificate file that the client trusts
# + key - Configurations associated with the `crypto:KeyStore` or combination of certificate and private key of the client
public type SecureSocket record {|
    boolean disable = false;
    crypto:TrustStore|string cert;
    crypto:KeyStore|CertKey key?;
|};

# Represents combination of certificate, private key and private key password if encrypted.
#
# + certFile - A file containing the certificate
# + keyFile - A file containing the private key
# + keyPassword - Password of the private key (if encrypted)
public type CertKey record {|
   string certFile;
   string keyFile;
   string keyPassword?;
|};

# Validates the provided JWT, against the provided configurations.
#```ballerina
# jwt:Payload|jwt:Error result = jwt:validate(jwt, validatorConfig);
# ```
#
# + jwt - JWT that needs to be validated
# + validatorConfig - JWT validator configurations
# + return - `jwt:Payload` or else a `jwt:Error` if token validation fails
public isolated function validate(string jwt, ValidatorConfig validatorConfig) returns Payload|Error {
    return validateJwt(jwt, validatorConfig);
}

isolated function validateJwt(string jwt, ValidatorConfig validatorConfig, cache:Cache? jwksCache = ())
                              returns Payload|Error {
    [Header, Payload] [header, payload] = check decode(jwt);
    if (!validateMandatoryHeaderFields(header)) {
        return prepareError("Mandatory field signing algorithm (alg) is not provided in JOSE header.");
    }
    _ = check validateJwtRecords(header, payload, validatorConfig);
    _ = check validateSignature(jwt, header, payload, validatorConfig, jwksCache);
    return payload;
}

# Decodes the provided JWT string.
# ```ballerina
# [jwt:Header, jwt:Payload]|jwt:Error [header, payload] = jwt:decode(jwt);
# ```
#
# + jwt - JWT that needs to be decoded
# + return - The `jwt:Header` and `jwt:Payload` as a  tuple or else a `jwt:Error` if token decoding fails
public isolated function decode(string jwt) returns [Header, Payload]|Error {
    string[] encodedJwtComponents = check getJwtComponents(jwt);
    Header header = check getHeader(encodedJwtComponents[0]);
    Payload payload = check getPayload(encodedJwtComponents[1]);
    return [header, payload];
}

isolated function getJwtComponents(string jwt) returns string[]|Error {
    string[] jwtComponents = regex:split(jwt, "\\.");
    if (jwtComponents.length() < 2 || jwtComponents.length() > 3) {
        return prepareError("Invalid JWT.");
    }
    return jwtComponents;
}

isolated function getHeader(string encodedHeader) returns Header|Error {
    byte[]|Error decodedHeader = decodeBase64Url(encodedHeader);
    if (decodedHeader is byte[]) {
        string|error result = 'string:fromBytes(decodedHeader);
        if (result is string) {
            json|error jsonHeader = result.fromJsonString();
            if (jsonHeader is json) {
                return parseHeader(<map<json>> jsonHeader);
            } else {
                return prepareError("String to JSON conversion failed for JWT header.", jsonHeader);
            }
        } else {
            return prepareError("Failed to convert byte[] of decoded header to string.", result);
        }
    } else {
        return prepareError("Base64 URL decode failed for JWT header.", decodedHeader);
    }
}

isolated function getPayload(string encodedPayload) returns Payload|Error {
    byte[]|Error decodedPayload = decodeBase64Url(encodedPayload);
    if (decodedPayload is byte[]) {
        string|error result = 'string:fromBytes(decodedPayload);
        if (result is string) {
            json|error jsonPayload = result.fromJsonString();
            if (jsonPayload is json) {
                return parsePayload(<map<json>> jsonPayload);
            } else {
                return prepareError("String to JSON conversion failed for JWT paylaod.", jsonPayload);
            }
        } else {
            return prepareError("Failed to convert byte[] of decoded payload to string.", result);
        }
    } else {
        return prepareError("Base64 URL decode failed for JWT payload.", decodedPayload);
    }
}

isolated function getJwtSignature(string encodedSignature) returns byte[]|Error {
    byte[]|Error signature = decodeBase64Url(encodedSignature);
    if (signature is byte[]) {
        return signature;
    } else {
        return prepareError("Base64 URL decode failed for JWT signature.", signature);
    }
}

isolated function parseHeader(map<json> headerMap) returns Header|Error {
    Header header = {};
    string[] keys = headerMap.keys();
    foreach string key in keys {
        match (key) {
            ALG => {
                if (headerMap[key].toJsonString() == "RS256") {
                    header.alg = RS256;
                } else if (headerMap[key].toJsonString() == "RS384") {
                    header.alg = RS384;
                } else if (headerMap[key].toJsonString() == "RS512") {
                    header.alg = RS512;
                } else {
                    return prepareError("Unsupported signing algorithm '" + headerMap[key].toJsonString() + "'.");
                }
            }
            TYP => {
                header.typ = headerMap[key].toJsonString();
            }
            CTY => {
                header.cty = headerMap[key].toJsonString();
            }
            KID => {
                header.kid = headerMap[key].toJsonString();
            }
            _ => {
                header[key] = headerMap[key].toJsonString();
            }
        }
    }
    return header;
}

isolated function parsePayload(map<json> payloadMap) returns Payload|Error {
    Payload payload = {};
    string[] keys = payloadMap.keys();
    foreach string key in keys {
        match (key) {
            ISS => {
                payload.iss = payloadMap[key].toJsonString();
            }
            SUB => {
                payload.sub = payloadMap[key].toJsonString();
            }
            AUD => {
                payload.aud = payloadMap[key] is json[] ? check convertToStringArray(<json[]>payloadMap[key]) : payloadMap[key].toJsonString();
            }
            JTI => {
                payload.jti = payloadMap[key].toJsonString();
            }
            EXP => {
                string exp = payloadMap[key].toJsonString();
                int|error value = 'int:fromString(exp);
                if (value is int) {
                    payload.exp = value;
                } else {
                    payload.exp = 0;
                }
            }
            NBF => {
                string nbf = payloadMap[key].toJsonString();
                int|error value = 'int:fromString(nbf);
                if (value is int) {
                    payload.nbf = value;
                } else {
                    payload.nbf = 0;
                }
            }
            IAT => {
                string iat = payloadMap[key].toJsonString();
                int|error value = 'int:fromString(iat);
                if (value is int) {
                    payload.iat = value;
                } else {
                    payload.iat = 0;
                }
            }
            _ => {
                payload[key] = payloadMap[key].toJsonString();
            }
        }
    }
    return payload;
}

isolated function validateSignature(string jwt, Header header, Payload payload, ValidatorConfig validatorConfig,
                                    cache:Cache? jwksCache) returns Error? {
    SigningAlgorithm alg = <SigningAlgorithm>header?.alg;  // The `()` value is already validated.
    ValidatorSignatureConfig? validatorSignatureConfig = validatorConfig?.signatureConfig;

    if (alg == NONE && validatorSignatureConfig is ()) {
        return;
    }

    if (alg == NONE && (validatorSignatureConfig is ValidatorSignatureConfig)) {
        return prepareError("Not a valid JWS. Signing algorithm is 'NONE'.");
    }

    string[] encodedJwtComponents = check getJwtComponents(jwt);
    if (alg != NONE && (validatorSignatureConfig is ValidatorSignatureConfig)) {
        if (encodedJwtComponents.length() == 2) {
            return prepareError("Not a valid JWS. Signature part is required.");
        }
    }

    string headerPayloadPart = encodedJwtComponents[0] + "." + encodedJwtComponents[1];
    byte[] assertion = headerPayloadPart.toBytes();
    byte[] signature = check getJwtSignature(encodedJwtComponents[2]);

    if (validatorSignatureConfig is ValidatorSignatureConfig) {
        var jwksConfig = validatorSignatureConfig?.jwksConfig;
        string? certFile = validatorSignatureConfig?.certFile;
        var trustStoreConfig = validatorSignatureConfig?.trustStoreConfig;
        if !(jwksConfig is ()) {
            string? kid = header?.kid;
            if (kid is string) {
                string url = <string> jwksConfig?.url;
                ClientConfiguration clientConfig = <ClientConfiguration> jwksConfig?.clientConfig;
                json jwk = check getJwk(kid, url, clientConfig, jwksCache);
                if (jwk is ()) {
                    return prepareError("No JWK found for kid '" + kid + "'.");
                }
                crypto:PublicKey publicKey = check getPublicKeyByJwks(jwk);
                boolean signatureValidation = check assertSignature(alg, assertion, signature, publicKey);
                if (!signatureValidation) {
                   return prepareError("JWT signature validation with JWKS configurations has failed.");
                }
            } else {
                return prepareError("Key ID (kid) is not provided in JOSE header.");
            }
        } else if (certFile is string) {
            crypto:PublicKey|crypto:Error publicKey = crypto:decodeRsaPublicKeyFromCertFile(certFile);
            if (publicKey is crypto:PublicKey) {
                if (!validateCertificate(publicKey)) {
                   return prepareError("Public key certificate validity period has passed.");
                }
                boolean signatureValidation = check assertSignature(alg, assertion, signature, publicKey);
                if (!signatureValidation) {
                   return prepareError("JWT signature validation with public key configurations has failed.");
                }
            } else {
                return prepareError("Failed to decode public key.", publicKey);
            }
        } else if !(trustStoreConfig is ()) {
            crypto:TrustStore trustStore = <crypto:TrustStore> trustStoreConfig?.trustStore;
            string certAlias = <string> trustStoreConfig?.certAlias;
            crypto:PublicKey|crypto:Error publicKey = crypto:decodeRsaPublicKeyFromTrustStore(trustStore, certAlias);
            if (publicKey is crypto:PublicKey) {
                if (!validateCertificate(publicKey)) {
                   return prepareError("Public key certificate validity period has passed.");
                }
                boolean signatureValidation = check assertSignature(alg, assertion, signature, publicKey);
                if (!signatureValidation) {
                   return prepareError("JWT signature validation with TrustStore configurations has failed.");
                }
            } else {
                return prepareError("Failed to decode public key.", publicKey);
            }
        }
    }
}

isolated function validateJwtRecords(Header header, Payload payload, ValidatorConfig validatorConfig) returns Error? {
    string? iss = validatorConfig?.issuer;
    if (iss is string) {
        _ = check validateIssuer(payload, iss);
    }
    string|string[]? aud = validatorConfig?.audience;
    if (aud is string || aud is string[]) {
        _ = check validateAudience(payload, aud);
    }
    int? exp = payload?.exp;
    if (exp is int) {
        if (!validateExpirationTime(exp, <int> validatorConfig.clockSkew)) {
            return prepareError("JWT is expired.");
        }
    }
    int? nbf = payload?.nbf;
    if (nbf is int) {
        if (!validateNotBeforeTime(nbf, <int> validatorConfig.clockSkew)) {
            return prepareError("JWT is used before not-before-time (nbf).");
        }
    }
}

isolated function validateMandatoryHeaderFields(Header header) returns boolean {
    SigningAlgorithm? alg = header?.alg;
    return alg is SigningAlgorithm;
}

isolated function validateCertificate(crypto:PublicKey publicKey) returns boolean {
    [int, decimal] currentTime = time:utcNow();
    crypto:Certificate? certificate = publicKey?.certificate;
    if (certificate is crypto:Certificate) {
        [int, decimal] notBefore = certificate.notBefore;
        [int, decimal] notAfter = certificate.notAfter;
        if (currentTime[0] >= notBefore[0] && currentTime[0] <= notAfter[0]) {
            return true;
        }
    }
    return false;
}

isolated function getPublicKeyByJwks(json jwk) returns crypto:PublicKey|Error {
    json|error modulus = jwk.n;
    json|error exponent = jwk.e;
    if (modulus is json && exponent is json) {
        crypto:PublicKey|crypto:Error publicKey = crypto:buildRsaPublicKey(modulus.toJsonString(), exponent.toJsonString());
        if (publicKey is crypto:PublicKey) {
            return publicKey;
        } else {
            return prepareError("Public key generation failed.", publicKey);
        }
    } else {
        return prepareError("Failed to access modulus and exponent from the JWK '" + jwk.toJsonString() + "'.");
    }
}

isolated function getJwk(string kid, string url, ClientConfiguration clientConfig, cache:Cache? jwksCache) returns json|Error {
    if (jwksCache is cache:Cache) {
        if (jwksCache.hasKey(kid)) {
            any|cache:Error jwk = jwksCache.get(kid);
            if (jwk is json) {
                return jwk;
            } else {
                log:printDebug("Failed to retrieve JWK for the kid '" + kid + "' from the cache.");
            }
        }
    }
    string|Error stringResponse = getJwksResponse(url, clientConfig);
    if (stringResponse is string) {
        json[] jwksArray = check getJwksArray(stringResponse);
        foreach json jwk in jwksArray {
            json|error responseKid = jwk.kid;
            if (responseKid is json && responseKid == kid) {
                return jwk;
            }
        }
    } else {
        return prepareError("Failed to call JWKS endpoint '" + url + "'.", stringResponse);
    }
}

isolated function getJwksArray(string stringResponse) returns json[]|Error {
    json|error jsonResponse = stringResponse.fromJsonString();
    if (jsonResponse is json) {
        json|error jwks = jsonResponse.keys;
        if (jwks is json) {
            return <json[]> jwks;
        } else {
            return prepareError("Failed to access 'keys' property from the JSON '" + jsonResponse.toJsonString() + "'.", jwks);
        }
    } else {
        return prepareError("Failed to convert '" + stringResponse + "' to JSON.", jsonResponse);
    }
}

isolated function getJwksResponse(string url, ClientConfiguration clientConfig) returns string|Error = @java:Method {
    'class: "org.ballerinalang.stdlib.jwt.JwksClient"
} external;

isolated function assertSignature(SigningAlgorithm alg, byte[] assertion, byte[] signaturePart,
                                  crypto:PublicKey publicKey) returns boolean|Error {
    match (alg) {
        RS256 => {
            boolean|crypto:Error result = crypto:verifyRsaSha256Signature(assertion, signaturePart, publicKey);
            if (result is boolean) {
                return result;
            } else {
                return prepareError("SHA256 signature verification failed.", result);
            }
        }
        RS384 => {
            boolean|crypto:Error result = crypto:verifyRsaSha384Signature(assertion, signaturePart, publicKey);
            if (result is boolean) {
                return result;
            } else {
                return prepareError("SHA384 signature verification failed.", result);
            }
        }
        RS512 => {
            boolean|crypto:Error result = crypto:verifyRsaSha512Signature(assertion, signaturePart, publicKey);
            if (result is boolean) {
                return result;
            } else {
                return prepareError("SHA512 signature verification failed.", result);
            }
        }
    }
    return prepareError("Unsupported JWS algorithm '" + alg.toString() + "'.");
}

isolated function validateIssuer(Payload payload, string issuerConfig) returns Error? {
    string? issuePayload = payload?.iss;
    if (issuePayload is string) {
        if (issuePayload != issuerConfig) {
            return prepareError("JWT contained invalid issuer name '" + issuePayload + "'");
        }
    } else {
        return prepareError("JWT must contain a valid issuer name.");
    }
}

isolated function validateAudience(Payload payload, string|string[] audienceConfig) returns Error? {
    string|string[]? audiencePayload = payload?.aud;
    if (audiencePayload is string) {
        if (audienceConfig is string) {
            if (audiencePayload == audienceConfig) {
                return;
            }
        } else {
            foreach string audience in audienceConfig {
                if (audience == audiencePayload) {
                    return;
                }
            }
        }
        return prepareError("Invalid audience.");
    } else if (audiencePayload is string[]) {
        if (audienceConfig is string) {
            foreach string audience in audiencePayload {
                if (audience == audienceConfig) {
                    return;
                }
            }
        } else {
            foreach string audienceC in audienceConfig {
                foreach string audienceP in audiencePayload {
                    if (audienceC == audienceP) {
                        return;
                    }
                }
            }
        }
        return prepareError("Invalid audience.");
    } else {
        return prepareError("JWT must contain a valid audience.");
    }
}

isolated function validateExpirationTime(int expTime, int clockSkew) returns boolean {
    [int, decimal] currentTime = time:utcNow();
    if (clockSkew > 0) {
        return expTime + clockSkew >= currentTime[0];
    } else {
        return expTime >= currentTime[0];
    }
}

isolated function validateNotBeforeTime(int nbf, int clockSkew) returns boolean {
    [int, decimal] currentTime = time:utcNow();
    if (clockSkew > 0) {
        return nbf - clockSkew <= currentTime[0];
    } else {
        return nbf <= currentTime[0];
    }
}

isolated function convertToStringArray(json[] jsonData) returns string[]|Error {
    string[] values = [];
    int i = 0;
    foreach json jsonVal in jsonData {
        values[i] = jsonVal.toJsonString();
        i = i + 1;
    }
    return values;
}
