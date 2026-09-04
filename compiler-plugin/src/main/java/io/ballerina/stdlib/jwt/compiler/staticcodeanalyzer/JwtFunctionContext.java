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

import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.SpecificFieldNode;
import io.ballerina.projects.Document;
import io.ballerina.scan.Reporter;
import io.ballerina.tools.diagnostics.Location;

import java.util.List;
import java.util.Optional;

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.findField;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.getArgument;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtAnalysisUtils.getNestedRecord;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.ISSUE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.ISSUER_CONFIG_PARAM;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.VALIDATE;
import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JwtConstants.VALIDATOR_CONFIG_PARAM;

/**
 * Represents the context of a JWT module function call being analyzed.
 * <p>
 * Every rule in this module needs the same two things: which JWT function was called, and the configuration record
 * behind its argument. The record is resolved once here, whether it was written inline at the call site or held in a
 * variable, so no rule has to walk the syntax tree for itself.
 *
 * @since 2.16.0
 */
public class JwtFunctionContext {

    private static final int ISSUER_CONFIG_POSITION = 0;
    private static final int VALIDATOR_CONFIG_POSITION = 1;

    private final Reporter reporter;
    private final Document document;
    private final String functionName;
    private final Location functionLocation;
    private final MappingConstructorExpressionNode configRecord;

    /**
     * Creates a context for the given JWT module function call.
     *
     * @param reporter     the static code analysis reporter
     * @param document     the document containing the call
     * @param functionName the simple name of the JWT function being called
     * @param functionCall the call being analyzed
     * @param siblingModuleParts the module's other documents, searched when the configuration is declared in one
     */
    public JwtFunctionContext(Reporter reporter, Document document, String functionName,
                              FunctionCallExpressionNode functionCall,
                              List<ModulePartNode> siblingModuleParts) {
        this.reporter = reporter;
        this.document = document;
        this.functionName = functionName;
        this.functionLocation = functionCall.location();
        this.configRecord = resolveConfigRecord(functionCall, functionName, siblingModuleParts);
    }

    /**
     * Resolve the configuration record the called function takes, if it takes one. {@code decode} has no
     * configuration, so a call to it leaves the record absent and only the rules that need no record apply.
     */
    private static MappingConstructorExpressionNode resolveConfigRecord(FunctionCallExpressionNode functionCall,
                                                                       String functionName,
                                                                       List<ModulePartNode> siblingModuleParts) {
        Optional<MappingConstructorExpressionNode> configRecord = switch (functionName) {
            case ISSUE -> getArgument(functionCall, ISSUER_CONFIG_POSITION, ISSUER_CONFIG_PARAM)
                    .flatMap(argument -> JwtAnalysisUtils.resolveConfigRecord(argument, siblingModuleParts));
            case VALIDATE -> getArgument(functionCall, VALIDATOR_CONFIG_POSITION, VALIDATOR_CONFIG_PARAM)
                    .flatMap(argument -> JwtAnalysisUtils.resolveConfigRecord(argument, siblingModuleParts));
            default -> Optional.empty();
        };
        return configRecord.orElse(null);
    }

    public Reporter getReporter() {
        return this.reporter;
    }

    public Document getDocument() {
        return this.document;
    }

    /**
     * The simple name of the JWT function that was called, such as {@code validate}.
     *
     * @return the called function's name
     */
    public String getFunctionName() {
        return this.functionName;
    }

    /**
     * The location of the whole call, used to report a check that is missing from the configuration. A record that
     * omits a field has no field to point at, so the call site is the closest thing to the defect.
     *
     * @return the location of the function call
     */
    public Location getFunctionLocation() {
        return this.functionLocation;
    }

    /**
     * Whether the configuration record behind the call could be resolved.
     *
     * @return true if a configuration record is available
     */
    public boolean hasConfigRecord() {
        return this.configRecord != null;
    }

    /**
     * Get a field of the configuration record.
     *
     * @param fieldName the field name to look for
     * @return the field if the record was resolved and carries it, empty otherwise
     */
    public Optional<SpecificFieldNode> getConfigField(String fieldName) {
        return this.configRecord == null ? Optional.empty() : findField(this.configRecord, fieldName);
    }

    /**
     * Get the value of a field of the configuration record.
     *
     * @param fieldName the field name to look for
     * @return the field's value if the record was resolved and carries it, empty otherwise
     */
    public Optional<ExpressionNode> getConfigFieldValue(String fieldName) {
        return getConfigField(fieldName).flatMap(SpecificFieldNode::valueExpr);
    }

    /**
     * Get a field of the configuration record whose value is itself a record.
     *
     * @param fieldName the field name to look for
     * @return the nested record if present, empty otherwise
     */
    public Optional<MappingConstructorExpressionNode> getNestedConfigRecord(String fieldName) {
        return this.configRecord == null ? Optional.empty() : getNestedRecord(this.configRecord, fieldName);
    }

    /**
     * Follow a chain of nested records, for a field that sits several levels inside the configuration.
     *
     * @param fieldNames the field names to follow, outermost first
     * @return the innermost record if the whole chain is present, empty otherwise
     */
    public Optional<MappingConstructorExpressionNode> getNestedConfigRecord(String... fieldNames) {
        Optional<MappingConstructorExpressionNode> current = Optional.ofNullable(this.configRecord);
        for (String fieldName : fieldNames) {
            current = current.flatMap(enclosingRecord -> getNestedRecord(enclosingRecord, fieldName));
        }
        return current;
    }

    /**
     * Report an issue against this call.
     *
     * @param location the location to report at
     * @param ruleId   the rule reporting the issue
     */
    public void reportIssue(Location location, int ruleId) {
        this.reporter.reportIssue(this.document, location, ruleId);
    }
}
