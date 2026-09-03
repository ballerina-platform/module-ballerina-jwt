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

package io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.jwtrules;

import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtFunctionContext;

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.findField;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.ALGORITHM;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.ISSUE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.SIGNATURE_CONFIG;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.AVOID_WEAK_CIPHER_ALGORITHMS;

/**
 * Rule to detect a token issued with the {@code NONE} signing algorithm.
 * <p>
 * A token signed with {@code NONE} carries no signature at all, so anyone can assemble one with whatever claims they
 * like and it will be accepted as genuine. That removes authentication entirely rather than weakening it.
 *
 * @since 2.15.0
 */
public class AvoidWeakCipherAlgorithmsRule implements JwtFunctionRule {

    private static final String NONE = "NONE";

    @Override
    public void analyze(JwtFunctionContext context) {
        boolean usesNoneAlgorithm = context.getNestedConfigRecord(SIGNATURE_CONFIG)
                .flatMap(signatureConfig -> findField(signatureConfig, ALGORITHM))
                .flatMap(algorithm -> algorithm.valueExpr())
                .map(value -> value.toSourceCode().trim())
                .filter(algorithm -> NONE.equals(algorithm) || algorithm.endsWith(":" + NONE))
                .isPresent();
        if (usesNoneAlgorithm) {
            context.reportIssue(context.getFunctionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_WEAK_CIPHER_ALGORITHMS.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return ISSUE.equals(context.getFunctionName()) && context.hasConfigRecord();
    }
}
