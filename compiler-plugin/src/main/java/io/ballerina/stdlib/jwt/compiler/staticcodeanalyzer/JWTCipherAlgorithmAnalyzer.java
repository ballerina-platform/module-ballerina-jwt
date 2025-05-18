/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer;

import io.ballerina.compiler.syntax.tree.*;
import io.ballerina.projects.Document;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;
import static io.ballerina.stdlib.jwt.compiler.Constants.*;

public class JWTCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;

    public JWTCipherAlgorithmAnalyzer(Reporter reporter) {
        this.reporter = reporter;
    }

    /**
     * Analyzes jwt:issue() calls and reports usage of signatureConfig.algorithm == NONE.
     * It checks inline mappings, function-local variables, and module-level variables.
     *
     * @param context the syntax node analysis context for reporting issues
     */
    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        FunctionCallExpressionNode functionCall = (FunctionCallExpressionNode) context.node();

        // Check if the function is qualified with the module name
        if (!(functionCall.functionName() instanceof QualifiedNameReferenceNode qualifiedName)) {
            return;
        }

        // Verify the module and function name
        if (!MODULE_NAME.equals(qualifiedName.modulePrefix().text()) || !FUNCTION_NAME.equals(qualifiedName.identifier().text())) {
            return;
        }

        for (FunctionArgumentNode arg : functionCall.arguments()) {
            if (!(arg instanceof PositionalArgumentNode posArg)) {
                continue;
            }
            ExpressionNode expr = posArg.expression();
            if (expr instanceof MappingConstructorExpressionNode mappingConstructor) {
                if (isInsecureInlineMappingLiteral(mappingConstructor)) {
                    reporter.reportIssue(
                            getDocument(context),
                            context.node().location(),
                            JWTRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId()
                    );
                }
            } else if (expr instanceof SimpleNameReferenceNode varRef) {
                if (isInsecureVariableReference(varRef)) {
                    reporter.reportIssue(
                            getDocument(context),
                            context.node().location(),
                            JWTRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId()
                    );
                }
            }
        }
    }

    /**
     * Determines if a variable reference refers to an IssuerConfig record with signatureConfig.algorithm == NONE.
     * It walks up the AST to check function bodies and module-level declarations.
     *
     * @param varRef the simple name reference node pointing to the variable
     * @return true if the variable's initializer mapping contains algorithm NONE, false otherwise
     */
    private boolean isInsecureVariableReference(SimpleNameReferenceNode varRef) {
        String varName = varRef.name().text();
        Node current = varRef.parent();
        while (current != null) {
            // Case 1: variable declared inside a function body
            if (current instanceof FunctionBodyBlockNode body) {
                for (StatementNode stmt : body.statements()) {
                    if (stmt instanceof VariableDeclarationNode varDecl
                            && varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode cap
                            && cap.variableName().text().equals(varName)
                            && varDecl.initializer().isPresent()
                            && varDecl.initializer().get() instanceof MappingConstructorExpressionNode mappingCtor) {
                        if (isInsecureInlineMappingLiteral(mappingCtor)) {
                            return true;
                        }
                    }
                }
            }
            // Case 3: variable declared at module level
            if (current instanceof ModulePartNode module) {
                for (ModuleMemberDeclarationNode member : module.members()) {
                    if (member instanceof ModuleVariableDeclarationNode varDecl
                            && varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode cap
                            && cap.variableName().text().equals(varName)
                            && varDecl.initializer().isPresent()
                            && varDecl.initializer().get() instanceof MappingConstructorExpressionNode mappingCtor
                            && isInsecureInlineMappingLiteral(mappingCtor)) {
                        return true;
                    }
                }
            }
            current = current.parent();
        }
        return false;
    }

    /**
     * Inspects a mapping constructor expression for signatureConfig.algorithm == NONE.
     *
     * @param mappingConstructor the mapping constructor expression node
     * @return true if the inline mapping specifies algorithm NONE, false otherwise
     */
    private boolean isInsecureInlineMappingLiteral(MappingConstructorExpressionNode mappingConstructor) {
        // Case 2: inline mapping literal
        for (MappingFieldNode field : mappingConstructor.fields()) {
            if (field instanceof SpecificFieldNode spec
                    && spec.fieldName().toString().contains(SIGNATURE_CONFIG)
                    && spec.valueExpr().isPresent()
                    && spec.valueExpr().get() instanceof MappingConstructorExpressionNode nested) {
                for (MappingFieldNode nestedField : nested.fields()) {
                    if (nestedField instanceof SpecificFieldNode algField
                            && algField.fieldName().toString().contains(ALGORITHM)
                            && algField.valueExpr().isPresent()
                            && algField.valueExpr().get().toString().contains(ALGORITHM_TYPE)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Retrieves the Document corresponding to the given syntax node analysis context.
     *
     * @param context the syntax node analysis context
     * @return the Document for the current module and document ID
     */
    public static Document getDocument(SyntaxNodeAnalysisContext context) {
        return context.currentPackage().module(context.moduleId()).document(context.documentId());
    }
}
