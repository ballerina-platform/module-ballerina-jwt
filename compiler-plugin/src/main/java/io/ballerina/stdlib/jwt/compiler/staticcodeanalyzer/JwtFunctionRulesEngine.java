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

import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.AvoidDisabledJwksTlsRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.AvoidLargeClockSkewRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.AvoidLongTokenExpiryRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.AvoidUnverifiedTokenDecodingRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.AvoidWeakCipherAlgorithmsRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.EnsureIssuerAndAudienceValidationRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.EnsureSignatureVerificationRule;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules.JwtFunctionRule;

import java.util.ArrayList;
import java.util.List;

/**
 * Engine to execute JWT function rules.
 *
 * @since 2.16.0
 */
public class JwtFunctionRulesEngine {

    private final List<JwtFunctionRule> rules;

    public JwtFunctionRulesEngine() {
        this.rules = new ArrayList<>();
        initializeDefaultRules();
    }

    public void executeRules(JwtFunctionContext context) {
        for (JwtFunctionRule rule : rules) {
            if (rule.isApplicable(context)) {
                rule.analyze(context);
            }
        }
    }

    public void addRule(JwtFunctionRule rule) {
        if (rule != null && !rules.contains(rule)) {
            rules.add(rule);
        }
    }

    private void initializeDefaultRules() {
        addRule(new AvoidWeakCipherAlgorithmsRule());
        addRule(new EnsureSignatureVerificationRule());
        addRule(new EnsureIssuerAndAudienceValidationRule());
        addRule(new AvoidLongTokenExpiryRule());
        addRule(new AvoidLargeClockSkewRule());
        addRule(new AvoidDisabledJwksTlsRule());
        addRule(new AvoidUnverifiedTokenDecodingRule());
        // Add more default rules here as needed
    }
}
