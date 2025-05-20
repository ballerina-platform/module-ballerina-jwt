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

import io.ballerina.compiler.syntax.tree.CaptureBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionArgumentNode;
import io.ballerina.compiler.syntax.tree.FunctionBodyBlockNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.ListBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ListConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingFieldNode;
import io.ballerina.compiler.syntax.tree.ModuleMemberDeclarationNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ModuleVariableDeclarationNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.PositionalArgumentNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SpecificFieldNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

/**
 * Analyzes JWT cipher algorithm usage in Ballerina code to detect insecure configurations.
 * <p>
 * This analysis task inspects calls to <code>jwt:issue()</code> and reports if the signature configuration uses
 * the insecure <code>NONE</code> algorithm. It checks for insecure usage in inline mapping literals, function-local
 * variables, and module-level variables.
 * </p>
 */
public class JWTCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private static final String JWT = "jwt";
    private static final String ISSUE = "issue";
    private static final String SIGNATURE_CONFIG = "signatureConfig";
    private static final String ALGORITHM = "algorithm";
    private static final String NONE = "NONE";

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
        if (!JWT.equals(qualifiedName.modulePrefix().text()) || !ISSUE.equals(qualifiedName.identifier().text())) {
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
                            getDocument(context.currentPackage().module(context.moduleId()), context.documentId()),
                            context.node().location(),
                            JWTRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId()
                    );
                }
            } else if (expr instanceof SimpleNameReferenceNode varRef) {
                if (isInsecureVariableReference(varRef)) {
                    reporter.reportIssue(
                            getDocument(context.currentPackage().module(context.moduleId()), context.documentId()),
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
                    // Simple case: variable declared inside a function body
                    if (stmt instanceof VariableDeclarationNode varDecl) {
                        if (varDecl.typedBindingPattern().bindingPattern()
                                instanceof CaptureBindingPatternNode captureBindingPattern
                                && captureBindingPattern.variableName().text().equals(varName)
                                && varDecl.initializer().isPresent()
                                && varDecl.initializer().get()
                                instanceof MappingConstructorExpressionNode mappingCtor) {
                            if (isInsecureInlineMappingLiteral(mappingCtor)) {
                                return true;
                            }
                        }
                        if (varDecl.typedBindingPattern().bindingPattern()
                                instanceof ListBindingPatternNode listBindingPattern
                                && listBindingPattern.bindingPatterns().get(0)
                                instanceof CaptureBindingPatternNode captureBindingPattern
                                && captureBindingPattern.variableName().text().equals(varName)
                                && varDecl.initializer().isPresent()
                                && varDecl.initializer().get()
                                instanceof ListConstructorExpressionNode listConstructorExpression
                                && listConstructorExpression.expressions().get(0)
                                instanceof MappingConstructorExpressionNode mappingCtor) {
                            if (isInsecureInlineMappingLiteral(mappingCtor)) {
                                return true;
                            }
                        }
                    }
                }
            }
            // Case 3: variable declared at module level
            if (current instanceof ModulePartNode module) {
                for (ModuleMemberDeclarationNode member : module.members()) {
                    if (member instanceof ModuleVariableDeclarationNode varDecl) {
                        if (varDecl.typedBindingPattern().bindingPattern()
                                instanceof CaptureBindingPatternNode captureBindingPattern
                                && captureBindingPattern.variableName().text().equals(varName)
                                && varDecl.initializer().isPresent()
                                && varDecl.initializer().get() instanceof MappingConstructorExpressionNode mappingCtor
                                && isInsecureInlineMappingLiteral(mappingCtor)) {
                            return true;
                        }
                        if (varDecl.typedBindingPattern().bindingPattern()
                                instanceof ListBindingPatternNode listBindingPattern
                                && listBindingPattern.bindingPatterns().get(0)
                                instanceof CaptureBindingPatternNode captureBindingPattern
                                && captureBindingPattern.variableName().text().equals(varName)
                                && varDecl.initializer().isPresent()
                                && varDecl.initializer().get()
                                instanceof ListConstructorExpressionNode listConstructorExpression
                                && listConstructorExpression.expressions().get(0)
                                instanceof MappingConstructorExpressionNode mappingCtor
                                && isInsecureInlineMappingLiteral(mappingCtor)) {
                            return true;
                        }
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
                            && algField.valueExpr().get().toString().contains(NONE)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Retrieves the Document corresponding to the given module and document ID.
     *
     * @param module     the module
     * @param documentId the document ID
     * @return the Document for the given module and document ID
     */
    private static Document getDocument(io.ballerina.projects.Module module,
                                        io.ballerina.projects.DocumentId documentId) {
        return module.document(documentId);
    }
}
