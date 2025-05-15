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

package io.ballerina.stdlib.jwt.compiler;

import io.ballerina.projects.plugins.CompilerPlugin;
import io.ballerina.projects.plugins.CompilerPluginContext;
import io.ballerina.scan.ScannerContext;
import io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JWTCodeAnalyzer;

/**
 * jwt compiler plugin.
 *
 * @since 2.15.1
 */
public class JWTCompilerPlugin extends CompilerPlugin {

    private static final String SCANNER_CONTEXT = "ScannerContext";

    @Override
    public void init(CompilerPluginContext context) {
        Object object = context.userData().get(SCANNER_CONTEXT);
        if (object instanceof ScannerContext scannerContext) {
            context.addCodeAnalyzer(new JWTCodeAnalyzer(scannerContext.getReporter()));
        }
    }
}
