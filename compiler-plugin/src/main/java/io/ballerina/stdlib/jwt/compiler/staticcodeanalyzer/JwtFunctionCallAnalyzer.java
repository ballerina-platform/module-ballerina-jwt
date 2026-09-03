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

import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.Optional;
import java.util.Set;

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.collectJwtPrefixes;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.getDocument;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.getJwtFunctionName;

/**
 * Analyzes calls into the {@code ballerina/jwt} module.
 * <p>
 * This task resolves the configuration record behind the call once and hands it to every rule, so a rule states the
 * property it cares about rather than repeating how to find it.
 *
 * @since 2.16.0
 */
public class JwtFunctionCallAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {

    private final Reporter reporter;
    private final JwtFunctionRulesEngine rulesEngine;

    public JwtFunctionCallAnalyzer(Reporter reporter) {
        this.reporter = reporter;
        this.rulesEngine = new JwtFunctionRulesEngine();
    }

    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        if (!(context.node() instanceof FunctionCallExpressionNode functionCall)) {
            return;
        }
        Set<String> jwtPrefixes = collectJwtPrefixes(context);
        Optional<String> functionName = getJwtFunctionName(functionCall, jwtPrefixes);
        if (functionName.isEmpty()) {
            return;
        }
        rulesEngine.executeRules(new JwtFunctionContext(reporter, getDocument(context), functionName.get(),
                functionCall));
    }
}
