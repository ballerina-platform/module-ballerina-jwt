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

/**
 * Interface to be implemented by all JWT function analysis rules.
 *
 * @since 2.16.0
 */
public interface JwtFunctionRule {

    /**
     * Analyze the given JWT function call and report issues if any.
     *
     * @param context Context information required to analyze the function call
     */
    void analyze(JwtFunctionContext context);

    /**
     * Get the unique rule ID for this rule.
     *
     * @return Unique rule ID
     */
    int getRuleId();

    /**
     * Check whether this rule is applicable for the given context.
     *
     * @param context Context information required to analyze the function call
     * @return true if the rule is applicable, false otherwise
     */
    boolean isApplicable(JwtFunctionContext context);
}
