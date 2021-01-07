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
import ballerina/encoding;
import ballerina/java;
import ballerina/lang.'int;
import ballerina/lang.'string;
import ballerina/log;
import ballerina/stringutils;
import ballerina/time;

# Represents JWT validator configurations.
#
# + issuer - Expected issuer
# + audience - Expected audience
# + clockSkewInSeconds - Clock skew in seconds
# + trustStoreConfig - JWT trust store configurations
# + jwksConfig - JWKs configurations
# + jwtCache - Cache used to store parsed JWT information
public type ValidatorConfig record {
    string issuer?;
    string|string[] audience?;
    int clockSkewInSeconds = 0;
    TrustStoreConfig trustStoreConfig?;
    JwksConfig jwksConfig?;
    cache:Cache jwtCache = new;
};

# Represents the JWKs endpoint configurations.
#
# + url - URL of the JWKs endpoint
# + jwksCache - Cache used to store preloaded JWKs information
# + clientConfig - HTTP client configurations which calls the JWKs endpoint
public type JwksConfig record {|
    string url;
    cache:Cache jwksCache?;
    ClientConfiguration clientConfig = {};
|};

# Represents the configurations of the client used to call the JWKs endpoint.
#
# + httpVersion - The HTTP version of the client
# + secureSocket - SSL/TLS related configurations
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
# + trustStore - Configurations associated with TrustStore
public type SecureSocket record {|
    boolean disable = false;
    crypto:TrustStore trustStore?;
|};

# Represents JWT trust store configurations.
#
# + trustStore - Trust store used for signature verification
# + certificateAlias - Token signed public key certificate alias
public type TrustStoreConfig record {|
    crypto:TrustStore trustStore;
    string certificateAlias;
|};

# Validates the provided JWT against the provided configurations.
#```ballerina
# jwt:Payload|jwt:Error result = jwt:validate(jwt, validatorConfig);
# ```
#
# + jwt - JWT that needs to be validated
# + validatorConfig - JWT validator configurations
# + return - `jwt:Payload` or else a `jwt:Error` if token validation fails
public isolated function validate(string jwt, ValidatorConfig validatorConfig) returns Payload|Error {
    if (validatorConfig.jwtCache.hasKey(jwt)) {
        Payload? payload = validateFromCache(validatorConfig.jwtCache, jwt);
        if (payload is Payload) {
            return payload;
        }
    }
    [Header, Payload] [header, payload] = check decode(jwt);
    _ = check validateJwtRecords(jwt, header, payload, validatorConfig);
    addToCache(validatorConfig.jwtCache, jwt, payload);
    return payload;
}

isolated function validateFromCache(cache:Cache jwtCache, string jwt) returns Payload? {
    Payload payload = <Payload>jwtCache.get(jwt);
    int? expTime = payload?.exp;
    // convert to current time and check the expiry time
    if (expTime is () || expTime > (time:currentTime().time / 1000)) {
        return payload;
    } else {
        cache:Error? result = jwtCache.invalidate(jwt);
        if (result is cache:Error) {
            log:printError("Failed to invalidate JWT from the cache. JWT payload: " + payload.toString());
        }
    }
}

isolated function addToCache(cache:Cache jwtCache, string jwt, Payload payload) {
    cache:Error? result = jwtCache.put(jwt, payload);
    if (result is cache:Error) {
        log:printError("Failed to add JWT to the cache. JWT payload: " + payload.toString());
        return;
    }
}

# Decodes the provided JWT string.
# ```ballerina
# [jwt:Header, jwt:Payload]|jwt:Error [header, payload] = jwt:decode(jwt);
# ```
#
# + jwt - JWT that needs to be decoded
# + return - The JWT header and payload tuple or else a `jwt:Error` if token decoding fails
public isolated function decode(string jwt) returns [Header, Payload]|Error {
    string[] encodedJwtComponents = check getJwtComponents(jwt);
    Header header = check getHeader(encodedJwtComponents[0]);
    Payload payload = check getPayload(encodedJwtComponents[1]);
    return [header, payload];
}

isolated function getJwtComponents(string jwt) returns string[]|Error {
    string[] jwtComponents = stringutils:split(jwt, "\\.");
    if (jwtComponents.length() < 2 || jwtComponents.length() > 3) {
        return prepareError("Invalid JWT.");
    }
    return jwtComponents;
}

isolated function getHeader(string encodedHeader) returns Header|Error {
    byte[]|error decodedHeader = encoding:decodeBase64Url(encodedHeader);
    if (decodedHeader is byte[]) {
        string|error result = 'string:fromBytes(decodedHeader);
        if (result is error) {
            return prepareError(result.message(), result);
        }
        string header = <string>result;
        json|error jsonHeader = header.fromJsonString();
        if (jsonHeader is error) {
            return prepareError("String to JSON conversion failed for JWT header.", jsonHeader);
        }
        return parseHeader(<map<json>>jsonHeader);
    } else {
        return prepareError("Base64 url decode failed for JWT header.", decodedHeader);
    }
}

isolated function getPayload(string encodedPayload) returns Payload|Error {
    byte[]|error decodedPayload = encoding:decodeBase64Url(encodedPayload);
    if (decodedPayload is byte[]) {
        string|error result = 'string:fromBytes(decodedPayload);
        if (result is error) {
            return prepareError(result.message(), result);
        }
        string payload = <string>result;
        json|error jsonPayload = payload.fromJsonString();
        if (jsonPayload is error) {
            return prepareError("String to JSON conversion failed for JWT paylaod.", jsonPayload);
        }
        return parsePayload(<map<json>>jsonPayload);
    } else {
        return prepareError("Base64 url decode failed for JWT payload.", decodedPayload);
    }
}

isolated function getJwtSignature(string encodedSignature) returns byte[]|Error {
    byte[]|encoding:Error signature = encoding:decodeBase64Url(encodedSignature);
    if (signature is encoding:Error) {
        return prepareError("Base64 url decode failed for JWT signature.", signature);
    }
    return <byte[]>signature;
}

isolated function parseHeader(map<json> headerMap) returns Header {
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

isolated function validateJwtRecords(string jwt, Header header, Payload payload, ValidatorConfig validatorConfig)
                                     returns Error? {
    if (!validateMandatoryHeaderFields(header)) {
        return prepareError("Mandatory field signing algorithm (alg) is not provided in JOSE header.");
    }

    SigningAlgorithm alg = <SigningAlgorithm>header?.alg;  // The `()` value is already validated.
    JwksConfig? jwksConfig = validatorConfig?.jwksConfig;
    TrustStoreConfig? trustStoreConfig = validatorConfig?.trustStoreConfig;
    if (jwksConfig is JwksConfig) {
        string? kid = header?.kid;
        if (kid is string) {
            _ = check validateSignatureByJwks(jwt, kid, alg, jwksConfig);
        } else if (trustStoreConfig is TrustStoreConfig) {
            _ = check validateSignatureByTrustStore(jwt, alg, trustStoreConfig);
        } else {
            return prepareError("Key ID (kid) is not provided in JOSE header.");
        }
    } else if (trustStoreConfig is TrustStoreConfig) {
        _ = check validateSignatureByTrustStore(jwt, alg, trustStoreConfig);
    }

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
        if (!validateExpirationTime(exp, validatorConfig.clockSkewInSeconds)) {
            return prepareError("JWT is expired.");
        }
    }
    int? nbf = payload?.nbf;
    if (nbf is int) {
        if (!validateNotBeforeTime(nbf)) {
            return prepareError("JWT is used before Not_Before_Time (nbf).");
        }
    }
    //TODO : Need to validate jwt id (jti) and custom claims.
    return ();
}

isolated function validateMandatoryHeaderFields(Header header) returns boolean {
    SigningAlgorithm? alg = header?.alg;
    return alg is SigningAlgorithm;
}

isolated function validateCertificate(crypto:PublicKey publicKey) returns boolean|Error {
    time:Time|time:Error result = time:toTimeZone(time:currentTime(), "GMT");
    if (result is time:Error) {
        return prepareError(result.message(), result);
    }

    time:Time currTimeInGmt = <time:Time>result;
    int currTimeInGmtMillis = currTimeInGmt.time;

    crypto:Certificate? certificate = publicKey?.certificate;
    if (certificate is crypto:Certificate) {
        int notBefore = certificate.notBefore.time;
        int notAfter = certificate.notAfter.time;
        if (currTimeInGmtMillis >= notBefore && currTimeInGmtMillis <= notAfter) {
            return true;
        }
    }
    return false;
}

isolated function validateSignatureByTrustStore(string jwt, SigningAlgorithm alg,
                                                TrustStoreConfig trustStoreConfig) returns Error? {
    crypto:PublicKey|crypto:Error publicKey = crypto:decodePublicKey(trustStoreConfig.trustStore,
                                                                     trustStoreConfig.certificateAlias);
    if (publicKey is crypto:Error) {
       return prepareError("Public key decode failed.", publicKey);
    }

    if (!check validateCertificate(<crypto:PublicKey>publicKey)) {
       return prepareError("Public key certificate validity period has passed.");
    }

    _ = check validateSignature(jwt, alg, <crypto:PublicKey>publicKey);
}

isolated function validateSignatureByJwks(string jwt, string kid, SigningAlgorithm alg, JwksConfig jwksConfig)
                                          returns Error? {
    json jwk = check getJwk(kid, jwksConfig);
    if (jwk is ()) {
        return prepareError("No JWK found for kid: " + kid);
    }
    string modulus = <string>jwk.n;
    string exponent = <string>jwk.e;
    crypto:PublicKey|crypto:Error publicKey = crypto:buildRsaPublicKey(modulus, exponent);
    if (publicKey is crypto:Error) {
       return prepareError("Public key generation failed.", publicKey);
    }
    _ = check validateSignature(jwt, alg, <crypto:PublicKey>publicKey);
}

isolated function validateSignature(string jwt, SigningAlgorithm alg, crypto:PublicKey publicKey) returns Error? {
    match (alg) {
        NONE => {
            return prepareError("Not a valid JWS. Signature algorithm is NONE.");
        }
        _ => {
            string[] encodedJwtComponents = check getJwtComponents(jwt);
            if (encodedJwtComponents.length() == 2) {
                return prepareError("Not a valid JWS. Signature is required.");
            }
            byte[] signature = check getJwtSignature(encodedJwtComponents[2]);
            string headerPayloadPart = encodedJwtComponents[0] + "." + encodedJwtComponents[1];
            byte[] assertion = headerPayloadPart.toBytes();
            boolean signatureValidation = check verifySignature(alg, assertion, signature, publicKey);
            if (!signatureValidation) {
               return prepareError("JWT signature validation has failed.");
            }
        }
    }
}

isolated function getJwk(string kid, JwksConfig jwksConfig) returns json|Error {
    cache:Cache? jwksCache = jwksConfig?.jwksCache;
    if (jwksCache is cache:Cache) {
        if (jwksCache.hasKey(kid)) {
            any|cache:Error jwk = jwksCache.get(kid);
            if (jwk is json) {
                return jwk;
            } else {
                log:print("Failed to retrieve JWK for the kid: " + kid + " from the cache.");
            }
        }
    }
    string|Error stringResponse = getJwksResponse(jwksConfig.url, jwksConfig.clientConfig);
    if (stringResponse is Error) {
        return prepareError("Failed to call JWKs endpoint.", stringResponse);
    }
    json[] jwksArray = check getJwksArray(<string>stringResponse);
    foreach json jwk in jwksArray {
        if (jwk.kid == kid) {
            return jwk;
        }
    }
}

isolated function getJwksArray(string stringResponse) returns json[]|Error {
    json|error jsonResponse = (<string>stringResponse).fromJsonString();
    if (jsonResponse is error) {
        return prepareError(jsonResponse.message(), jsonResponse);
    }
    json payload = <json>jsonResponse;
    json[] jwks = <json[]>(payload.keys);
    return jwks;
}

isolated function getJwksResponse(string url, ClientConfiguration clientConfig) returns string|Error = @java:Method {
    'class: "org.ballerinalang.stdlib.jwt.JwksClient"
} external;

isolated function verifySignature(SigningAlgorithm alg, byte[] assertion, byte[] signaturePart,
                                  crypto:PublicKey publicKey) returns boolean|Error {
    match (alg) {
        RS256 => {
            boolean|crypto:Error result = crypto:verifyRsaSha256Signature(assertion, signaturePart, publicKey);
            if (result is boolean) {
                return result;
            } else {
                return prepareError("SHA256 singature verification failed.", result);
            }
        }
        RS384 => {
            boolean|crypto:Error result = crypto:verifyRsaSha384Signature(assertion, signaturePart, publicKey);
            if (result is boolean) {
                return result;
            } else {
                return prepareError("SHA384 singature verification failed.", result);
            }
        }
        RS512 => {
            boolean|crypto:Error result = crypto:verifyRsaSha512Signature(assertion, signaturePart, publicKey);
            if (result is boolean) {
                return result;
            } else {
                return prepareError("SHA512 singature verification failed.", result);
            }
        }
    }
    return prepareError("Unsupported JWS algorithm.");
}

isolated function validateIssuer(Payload payload, string issuerConfig) returns Error? {
    string? issuePayload = payload?.iss;
    if (issuePayload is string) {
        if (issuePayload != issuerConfig) {
            return prepareError("JWT contained invalid issuer name : " + issuePayload);
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
                return ();
            }
        } else {
            foreach string audience in audienceConfig {
                if (audience == audiencePayload) {
                    return ();
                }
            }
        }
        return prepareError("Invalid audience.");
    } else if (audiencePayload is string[]) {
        if (audienceConfig is string) {
            foreach string audience in audiencePayload {
                if (audience == audienceConfig) {
                    return ();
                }
            }
        } else {
            foreach string audienceC in audienceConfig {
                foreach string audienceP in audiencePayload {
                    if (audienceC == audienceP) {
                        return ();
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
    //Convert current time which is in milliseconds to seconds.
    if (clockSkew > 0) {
        return expTime + clockSkew > time:currentTime().time / 1000;
    } else {
        return expTime > time:currentTime().time / 1000;
    }
}

isolated function validateNotBeforeTime(int nbf) returns boolean {
    return time:currentTime().time > nbf;
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
