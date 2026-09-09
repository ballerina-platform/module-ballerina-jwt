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

import io.ballerina.compiler.syntax.tree.SpecificFieldNode;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtFunctionContext;

import java.util.Optional;

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.findField;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.CLIENT_CONFIG;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.DISABLE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.JWKS_CONFIG;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.SECURE_SOCKET;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.SIGNATURE_CONFIG;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.VALIDATE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtRule.AVOID_DISABLED_JWKS_TLS;

/**
 * Rule to detect a JWKS endpoint client whose TLS validation has been disabled.
 * <p>
 * The signing keys are fetched over that client, so accepting any certificate there means accepting keys from any
 * host that can answer for the JWKS URL. An attacker able to do that supplies their own signing key, and every
 * signature check downstream then passes against it — the validator keeps working, and validates the wrong thing.
 *
 * @since 2.16.0
 */
public class AvoidDisabledJwksTlsRule implements JwtFunctionRule {

    @Override
    public void analyze(JwtFunctionContext context) {
        Optional<SpecificFieldNode> disable = context
                .getNestedConfigRecord(SIGNATURE_CONFIG, JWKS_CONFIG, CLIENT_CONFIG, SECURE_SOCKET)
                .flatMap(secureSocket -> findField(secureSocket, DISABLE));
        if (disable.isEmpty() || disable.get().valueExpr().isEmpty()) {
            return;
        }
        if (context.getBooleanValue(disable.get().valueExpr().get()).orElse(false)) {
            context.reportIssue(disable.get().location(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_DISABLED_JWKS_TLS.getId();
    }

    @Override
    public boolean isApplicable(JwtFunctionContext context) {
        return VALIDATE.equals(context.getFunctionName()) && context.hasConfigRecord();
    }
}
