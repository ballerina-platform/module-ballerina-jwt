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

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.DECODE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.AVOID_UNVERIFIED_TOKEN_DECODING;

/**
 * Rule to detect a token read through {@code jwt:decode}.
 * <p>
 * {@code decode} splits a token and returns its header and payload without checking the signature, the issuer, the
 * audience or the expiry. The claims it returns are whatever the sender wrote, so any decision made from them is a
 * decision made on attacker-supplied data. {@code jwt:validate} is the function that establishes trust.
 * <p>
 * Reading the header before validating, to pick a key by {@code kid}, is a legitimate use. This rule reports the
 * call for review rather than asserting a defect, so a deliberate decode is expected to be reviewed and suppressed.
 *
 * @since 2.16.0
 */
public class AvoidUnverifiedTokenDecodingRule implements JwtFunctionRule {

    @Override
    public void analyze(JwtFunctionContext context) {
        context.reportIssue(context.getFunctionLocation(), getRuleId());
    }

    @Override
    public int getRuleId() {
        return AVOID_UNVERIFIED_TOKEN_DECODING.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return DECODE.equals(context.getFunctionName());
    }
}
