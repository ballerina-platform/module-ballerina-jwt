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

import java.math.BigDecimal;

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.EXP_TIME;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.ISSUE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.AVOID_LONG_TOKEN_EXPIRY;

/**
 * Rule to detect a token issued with an excessively long lifetime.
 * <p>
 * A JWT cannot be withdrawn once issued, so its lifetime is exactly how long an attacker keeps access after stealing
 * one. The module's own default is 300 seconds; the threshold here is a full day, so the rule reports only lifetimes
 * well past anything a deployment would choose deliberately.
 *
 * @since 2.16.0
 */
public class AvoidLongTokenExpiryRule implements JwtFunctionRule {

    private static final BigDecimal MAX_EXPIRY_SECONDS = BigDecimal.valueOf(86400);

    @Override
    public void analyze(JwtFunctionContext context) {
        context.getConfigField(EXP_TIME).ifPresent(expTime -> expTime.valueExpr()
                .flatMap(context::getNumericValue)
                .filter(seconds -> seconds.compareTo(MAX_EXPIRY_SECONDS) > 0)
                .ifPresent(seconds -> context.reportIssue(expTime.location(), getRuleId())));
    }

    @Override
    public int getRuleId() {
        return AVOID_LONG_TOKEN_EXPIRY.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return ISSUE.equals(context.getFunctionName()) && context.hasConfigRecord();
    }
}
