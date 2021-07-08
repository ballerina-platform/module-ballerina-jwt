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

package io.ballerina.stdlib.jwt;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;

/**
 * Constants related to Ballerina JWT stdlib.
 */
public class JwtConstants {

    private JwtConstants() {}

    public static final String JWT_ERROR_TYPE = "Error";

    public static final BString HTTP_VERSION = StringUtils.fromString("httpVersion");
    public static final BString SECURE_SOCKET = StringUtils.fromString("secureSocket");
    public static final BString DISABLE = StringUtils.fromString("disable");
    public static final BString CERT = StringUtils.fromString("cert");
    public static final BString KEY = StringUtils.fromString("key");
    public static final BString CERT_FILE = StringUtils.fromString("certFile");
    public static final BString KEY_FILE = StringUtils.fromString("keyFile");
    public static final BString KEY_PASSWORD = StringUtils.fromString("keyPassword");
    public static final BString PATH = StringUtils.fromString("path");
    public static final BString PASSWORD = StringUtils.fromString("password");

    public static final String TLS = "TLS";
    public static final String PKCS12 = "PKCS12";
    public static final String HTTP_2 = "HTTP_2";

    public static final String NATIVE_DATA_PUBLIC_KEY_CERTIFICATE = "NATIVE_DATA_PUBLIC_KEY_CERTIFICATE";
    public static final String NATIVE_DATA_PRIVATE_KEY = "NATIVE_DATA_PRIVATE_KEY";
}
