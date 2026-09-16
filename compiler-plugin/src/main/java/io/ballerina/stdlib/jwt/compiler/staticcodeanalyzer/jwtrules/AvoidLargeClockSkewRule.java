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

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.CLOCK_SKEW;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.VALIDATE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.AVOID_LARGE_CLOCK_SKEW;

/**
 * Rule to detect a validator configured with an excessively large clock skew.
 * <p>
 * Skew is allowed on both ends of every expiry check, so it silently extends the lifetime of every token the service
 * accepts, including ones already expired. The module's default is zero, and a few minutes covers any realistic
 * clock drift between hosts.
 *
 * @since 2.16.0
 */
public class AvoidLargeClockSkewRule implements JwtFunctionRule {

    private static final BigDecimal MAX_CLOCK_SKEW_SECONDS = BigDecimal.valueOf(300);

    @Override
    public void analyze(JwtFunctionContext context) {
        context.getConfigField(CLOCK_SKEW).ifPresent(clockSkew -> clockSkew.valueExpr()
                .flatMap(context::getNumericValue)
                .filter(seconds -> seconds.compareTo(MAX_CLOCK_SKEW_SECONDS) > 0)
                .ifPresent(seconds -> context.reportIssue(clockSkew.location(), getRuleId())));
    }

    @Override
    public int getRuleId() {
        return AVOID_LARGE_CLOCK_SKEW.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return VALIDATE.equals(context.getFunctionName()) && context.hasConfigRecord();
    }
}
