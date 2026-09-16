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
    AVOID_WEAK_CIPHER_ALGORITHMS(createRule(1, "A JSON Web Token is signed or verified with a weak or " +
            "unsuitable algorithm.", VULNERABILITY)),
    ENSURE_SIGNATURE_VERIFICATION(createRule(2, "A JSON Web Token is validated without a signature " +
            "configuration, so its signature is never verified.", VULNERABILITY)),
    ENSURE_ISSUER_AND_AUDIENCE_VALIDATION(createRule(3, "A JSON Web Token is validated without checking that " +
            "the issuer and the audience match what the service expects.", VULNERABILITY)),
    AVOID_LONG_TOKEN_EXPIRY(createRule(4, "A JSON Web Token is issued with an expiry time that is longer than " +
            "necessary.", VULNERABILITY)),
    AVOID_LARGE_CLOCK_SKEW(createRule(5, "A JSON Web Token is validated with a clock skew allowance that is " +
            "larger than necessary.", VULNERABILITY)),
    AVOID_DISABLED_JWKS_TLS(createRule(6, "TLS certificate validation is disabled on the client used to fetch " +
            "signing keys from a JWKS endpoint.", VULNERABILITY)),
    AVOID_UNVERIFIED_TOKEN_DECODING(createRule(7, "A JSON Web Token is decoded without verifying its signature, " +
            "issuer, audience, or expiry.", VULNERABILITY));

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
