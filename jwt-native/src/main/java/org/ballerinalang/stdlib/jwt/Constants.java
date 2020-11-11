package org.ballerinalang.stdlib.jwt;

import io.ballerina.runtime.api.Module;

import static io.ballerina.runtime.api.constants.RuntimeConstants.BALLERINA_BUILTIN_PKG_PREFIX;

/**
 * Constants related to Ballerina jwt stdlib.
 */
public class Constants {
    public static final String PACKAGE_NAME = "jwt";
    public static final Module JWT_PACKAGE_ID = new Module(BALLERINA_BUILTIN_PKG_PREFIX, PACKAGE_NAME, "1.0.4");
    public static final String JWT_ERROR_TYPE = "JwtError";
}
