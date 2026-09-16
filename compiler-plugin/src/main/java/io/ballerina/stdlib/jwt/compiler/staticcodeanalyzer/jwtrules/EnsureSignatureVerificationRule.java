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

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.SIGNATURE_CONFIG;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.VALIDATE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.ENSURE_SIGNATURE_VERIFICATION;

/**
 * Rule to detect a validator configuration that carries no signature configuration.
 * <p>
 * {@code signatureConfig} is optional, and leaving it out removes the signature check rather than falling back to a
 * safe default. A token anyone assembled and self-signed is then accepted on the same terms as one the identity
 * provider issued, while the calling code reads the claims as though they had been verified.
 *
 * @since 2.16.0
 */
public class EnsureSignatureVerificationRule implements JwtFunctionRule {

    @Override
    public void analyze(JwtFunctionContext context) {
        if (context.getConfigField(SIGNATURE_CONFIG).isEmpty()) {
            context.reportIssue(context.getFunctionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return ENSURE_SIGNATURE_VERIFICATION.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return VALIDATE.equals(context.getFunctionName()) && context.hasConfigRecord();
    }
}
