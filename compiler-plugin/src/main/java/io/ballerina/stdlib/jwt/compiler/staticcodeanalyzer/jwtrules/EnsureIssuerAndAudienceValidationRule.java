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

import java.util.List;

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.AUDIENCE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.ISSUER;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.VALIDATE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.ENSURE_ISSUER_AND_AUDIENCE_VALIDATION;

/**
 * Rule to detect a validator configuration that does not pin the issuer and the audience.
 * <p>
 * A verified signature proves only that the token was minted by a key the service trusts. Without {@code issuer} and
 * {@code audience}, a token that same key issued for a different service, or a different tenant, is accepted here as
 * well, which turns one service's token into a key to all of them.
 *
 * @since 2.16.0
 */
public class EnsureIssuerAndAudienceValidationRule implements JwtFunctionRule {

    @Override
    public void analyze(JwtFunctionContext context) {
        // One report per configuration: the defect is the missing check, and naming both fields twice on a record
        // that omits both says nothing more than naming it once.
        for (String field : List.of(ISSUER, AUDIENCE)) {
            if (context.getConfigField(field).isEmpty()) {
                context.reportIssue(context.getFunctionLocation(), getRuleId());
                return;
            }
        }
    }

    @Override
    public int getRuleId() {
        return ENSURE_ISSUER_AND_AUDIENCE_VALIDATION.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return VALIDATE.equals(context.getFunctionName()) && context.hasConfigRecord();
    }
}
