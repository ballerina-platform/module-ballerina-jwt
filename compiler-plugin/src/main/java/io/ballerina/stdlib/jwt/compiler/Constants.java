package io.ballerina.stdlib.jwt.compiler;

public final class Constants {
    private Constants() {
    }

    public static final String JWT = "jwt";
    public static final String ISSUE = "issue";
    public static final String SIGNATURE_CONFIG = "signatureConfig";
    public static final String ALGORITHM = "algorithm";
    public static final String NONE = "NONE";

    public static final String AVOID_WEAK_CIPHER_ALGORITHMS_LITERAL = "JWT should be signed and verified with "
            + "strong cipher algorithms";
}
