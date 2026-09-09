/*
 *  Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 *  OF ANY KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer;

import io.ballerina.scan.Rule;

import static io.ballerina.scan.RuleKind.VULNERABILITY;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.RuleFactory.createRule;

public enum JwtRule {
    AVOID_WEAK_CIPHER_ALGORITHMS(createRule(1, "Avoid using weak cipher algorithms when signing and " +
            "verifying JWTs", VULNERABILITY)),
    ENSURE_SIGNATURE_VERIFICATION(createRule(2, "Avoid validating JSON Web Tokens without a signature " +
            "configuration", VULNERABILITY)),
    ENSURE_ISSUER_AND_AUDIENCE_VALIDATION(createRule(3, "Avoid validating JSON Web Tokens without checking the " +
            "issuer and the audience", VULNERABILITY)),
    AVOID_LONG_TOKEN_EXPIRY(createRule(4, "Avoid issuing JSON Web Tokens with a long expiry time", VULNERABILITY)),
    AVOID_LARGE_CLOCK_SKEW(createRule(5, "Avoid validating JSON Web Tokens with a large clock skew", VULNERABILITY)),
    AVOID_DISABLED_JWKS_TLS(createRule(6, "Avoid disabling TLS validation on the JWKS endpoint client",
            VULNERABILITY)),
    AVOID_UNVERIFIED_TOKEN_DECODING(createRule(7, "Avoid decoding JSON Web Tokens without verifying them",
            VULNERABILITY));

    private final Rule rule;

    JwtRule(Rule rule) {
        this.rule = rule;
    }

    public int getId() {
        return this.rule.numericId();
    }

    public String getDescription() {
        return this.rule.description();
    }

    @Override
    public String toString() {
        return "{\"id\":" + this.getId() + ", \"kind\":\"" + this.rule.kind() + "\"," +
                " \"description\" : \"" + this.rule.description() + "\"}";
    }
}
