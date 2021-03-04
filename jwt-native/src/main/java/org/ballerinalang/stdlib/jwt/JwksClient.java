/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.ballerinalang.stdlib.jwt;

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import org.ballerinalang.stdlib.crypto.nativeimpl.Decode;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Extern function to call JWKs endpoint using the JDK11 HttpClient and return the payload of the HTTP response.
 */
public class JwksClient {

    public static Object getJwksResponse(BString url, BMap<BString, Object> clientConfig) {
        HttpRequest request = buildHttpRequest(url.getValue());
        String httpVersion = getBStringValueIfPresent(clientConfig, JwtConstants.HTTP_VERSION).getValue();
        BMap<BString, Object> secureSocket =
                (BMap<BString, Object>) getBMapValueIfPresent(clientConfig, JwtConstants.SECURE_SOCKET);
        if (secureSocket != null) {
            try {
                SSLContext sslContext = getSslContext(secureSocket);
                HttpClient client = buildHttpClient(httpVersion, sslContext);
                return callEndpoint(client, request);
            } catch (Exception e) {
                return createError("Failed to init SSL context. " + e.getMessage());
            }
        }
        HttpClient client = buildHttpClient(httpVersion);
        return callEndpoint(client, request);
    }

    private static SSLContext getSslContext(BMap<BString, Object> secureSocket) throws Exception {
        boolean disable = secureSocket.getBooleanValue(JwtConstants.DISABLE);
        Object cert = secureSocket.get(JwtConstants.CERT);
        BMap<BString, BString> key = (BMap<BString, BString>) getBMapValueIfPresent(secureSocket,
                                                                                    JwtConstants.KEY);
        if (disable) {
            return initSslContext();
        }
        if (cert instanceof BString) {
            if (key != null) {
                if (key.containsKey(JwtConstants.CERT_FILE)) {
                    BString certFile = key.get(JwtConstants.CERT_FILE);
                    BString keyFile = key.get(JwtConstants.KEY_FILE);
                    BString keyPassword = getBStringValueIfPresent(key, JwtConstants.KEY_PASSWORD);
                    return initSslContext((BString) cert, certFile, keyFile, keyPassword);
                } else {
                    return initSslContext((BString) cert, key);
                }
            } else {
                return initSslContext((BString) cert);
            }
        }
        if (cert instanceof BMap) {
            BMap<BString, BString> trustStore = (BMap<BString, BString>) cert;
            if (key != null) {
                if (key.containsKey(JwtConstants.CERT_FILE)) {
                    BString certFile = key.get(JwtConstants.CERT_FILE);
                    BString keyFile = key.get(JwtConstants.KEY_FILE);
                    BString keyPassword = getBStringValueIfPresent(key, JwtConstants.KEY_PASSWORD);
                    return initSslContext(trustStore, certFile, keyFile, keyPassword);
                } else {
                    return initSslContext(trustStore, key);
                }
            } else {
                return initSslContext(trustStore);
            }
        }
        return null;
    }

    private static HttpClient.Version getHttpVersion(String httpVersion) {
        if (JwtConstants.HTTP_2.equals(httpVersion)) {
            return HttpClient.Version.HTTP_2;
        }
        return HttpClient.Version.HTTP_1_1;
    }

    private static SSLContext initSslContext() throws Exception {
        TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };
        return buildSslContext(null, trustManagers);
    }

    private static SSLContext initSslContext(BMap<BString, BString> trustStore) throws Exception {
        BString path = trustStore.getStringValue(JwtConstants.PATH);
        BString password = trustStore.getStringValue(JwtConstants.PASSWORD);
        KeyStore ts = getKeyStore(path, password);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        return buildSslContext(null, tmf.getTrustManagers());
    }

    private static SSLContext initSslContext(BString cert) throws Exception {
        KeyStore ts = buildTrustStore(cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        return buildSslContext(null, tmf.getTrustManagers());
    }

    private static SSLContext initSslContext(BMap<BString, BString> trustStore, BMap<BString, BString> keyStore)
            throws Exception {
        BString trustStorePath = trustStore.getStringValue(JwtConstants.PATH);
        BString trustStorePassword = trustStore.getStringValue(JwtConstants.PASSWORD);
        KeyStore ts = getKeyStore(trustStorePath, trustStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        BString keyStorePath = keyStore.getStringValue(JwtConstants.PATH);
        BString keyStorePassword = keyStore.getStringValue(JwtConstants.PASSWORD);
        KeyStore ks = getKeyStore(keyStorePath, keyStorePassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyStorePassword.getValue().toCharArray());
        return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
    }

    private static SSLContext initSslContext(BMap<BString, BString> trustStore, BString certFile, BString keyFile,
                                             BString keyPassword) throws Exception {
        BString trustStorePath = trustStore.getStringValue(JwtConstants.PATH);
        BString trustStorePassword = trustStore.getStringValue(JwtConstants.PASSWORD);
        KeyStore ts = getKeyStore(trustStorePath, trustStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        KeyStore ks = buildKeyStore(certFile, keyFile, keyPassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "".toCharArray());
        return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
    }

    private static SSLContext initSslContext(BString cert, BString certFile, BString keyFile,
                                             BString keyPassword) throws Exception {
        KeyStore ts = buildTrustStore(cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        KeyStore ks = buildKeyStore(certFile, keyFile, keyPassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "".toCharArray());
        return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
    }

    private static SSLContext initSslContext(BString cert, BMap<BString, BString> keyStore) throws Exception {
        KeyStore ts = buildTrustStore(cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        BString keyStorePath = keyStore.getStringValue(JwtConstants.PATH);
        BString keyStorePassword = keyStore.getStringValue(JwtConstants.PASSWORD);
        KeyStore ks = getKeyStore(keyStorePath, keyStorePassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyStorePassword.getValue().toCharArray());

        return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
    }

    private static KeyStore getKeyStore(BString path, BString password) throws Exception {
        try (FileInputStream is = new FileInputStream(path.getValue())) {
            char[] passphrase = password.getValue().toCharArray();
            KeyStore ks = KeyStore.getInstance(JwtConstants.PKCS12);
            ks.load(is, passphrase);
            return ks;
        }
    }

    private static KeyStore buildTrustStore(BString path) throws Exception {
        Object publicKeyMap = Decode.decodeRsaPublicKeyFromCertFile(path);
        if (publicKeyMap instanceof BMap) {
            X509Certificate x509Certificate = (X509Certificate) ((BMap<BString, Object>) publicKeyMap).getNativeData(
                    JwtConstants.NATIVE_DATA_PUBLIC_KEY_CERTIFICATE);
            KeyStore truststore = KeyStore.getInstance(JwtConstants.PKCS12);
            truststore.load(null, "".toCharArray());
            truststore.setCertificateEntry(UUID.randomUUID().toString(), x509Certificate);
            return truststore;
        } else {
            throw new Exception("Failed to get the public key from Crypto API. " +
                                        ((BError) publicKeyMap).getErrorMessage().getValue());
        }
    }

    private static KeyStore buildKeyStore(BString certPath, BString keyPath, BString keyPassword) throws Exception {
        Object publicKey = Decode.decodeRsaPublicKeyFromCertFile(certPath);
        if (publicKey instanceof BMap) {
            X509Certificate publicCert = (X509Certificate) ((BMap<BString, Object>) publicKey).getNativeData(
                    JwtConstants.NATIVE_DATA_PUBLIC_KEY_CERTIFICATE);
            Object privateKeyMap = Decode.decodeRsaPrivateKeyFromKeyFile(keyPath, keyPassword);
            if (privateKeyMap instanceof BMap) {
                PrivateKey privateKey = (PrivateKey) ((BMap<BString, Object>) privateKeyMap).getNativeData(
                        JwtConstants.NATIVE_DATA_PRIVATE_KEY);
                KeyStore ks = KeyStore.getInstance(JwtConstants.PKCS12);
                ks.load(null, "".toCharArray());
                ks.setKeyEntry(UUID.randomUUID().toString(), privateKey, "".toCharArray(),
                               new X509Certificate[]{publicCert});
                return ks;
            } else {
                throw new Exception("Failed to get the private key from Crypto API. " +
                                            ((BError) privateKeyMap).getErrorMessage().getValue());
            }
        } else {
            throw new Exception("Failed to get the public key from Crypto API. " +
                                        ((BError) publicKey).getErrorMessage().getValue());
        }
    }

    private static SSLContext buildSslContext(KeyManager[] keyManagers, TrustManager[] trustManagers) throws Exception {
        SSLContext sslContext = SSLContext.getInstance(JwtConstants.TLS);
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        return sslContext;
    }

    private static HttpClient buildHttpClient(String httpVersion) {
        return HttpClient.newBuilder().version(getHttpVersion(httpVersion)).build();
    }

    private static HttpClient buildHttpClient(String httpVersion, SSLContext sslContext) {
        return HttpClient.newBuilder().version(getHttpVersion(httpVersion)).sslContext(sslContext).build();
    }

    private static HttpRequest buildHttpRequest(String url) {
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
    }

    private static Object callEndpoint(HttpClient client, HttpRequest request) {
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return StringUtils.fromString(response.body());
            }
            return JwtUtils.createError("Failed to get a success response from JWKs endpoint. Response Code: '" +
                                                response.statusCode() + "'. Response Body: '" + response.body() + "'");
        } catch (IOException | InterruptedException e) {
            return JwtUtils.createError("Failed to send the request to JWKs endpoint. " + e.getMessage());
        }
    }

    private static BMap<?, ?> getBMapValueIfPresent(BMap<BString, ?> config, BString key) {
        return config.containsKey(key) ? config.getMapValue(key) : null;
    }

    private static BString getBStringValueIfPresent(BMap<BString, ?> config, BString key) {
        return config.containsKey(key) ? config.getStringValue(key) : null;
    }

    private static BError createError(String errMsg) {
        return ErrorCreator.createDistinctError(JwtConstants.JWT_ERROR_TYPE, ModuleUtils.getModule(),
                                                StringUtils.fromString(errMsg));
    }
}
