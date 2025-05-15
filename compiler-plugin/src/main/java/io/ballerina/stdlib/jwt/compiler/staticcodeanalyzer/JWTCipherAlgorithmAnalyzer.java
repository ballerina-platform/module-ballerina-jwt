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
import io.ballerina.compiler.syntax.tree.ImportOrgNameNode;
import io.ballerina.compiler.syntax.tree.ImportPrefixNode;
import io.ballerina.compiler.syntax.tree.ListBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ListConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingFieldNode;
import io.ballerina.compiler.syntax.tree.ModuleMemberDeclarationNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ModuleVariableDeclarationNode;
import io.ballerina.compiler.syntax.tree.NamedArgumentNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.NodeList;
import io.ballerina.compiler.syntax.tree.PositionalArgumentNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SpecificFieldNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.HashSet;
import java.util.Set;

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
    private static final String BALLERINA_ORG = "ballerina";

    private final Set<String> jwtPrefixes = new HashSet<>();

    public JWTCipherAlgorithmAnalyzer(Reporter reporter) {
        this.reporter = reporter;
        this.jwtPrefixes.add(JWT);
    }

    /**
     * Analyzes jwt:issue() calls and reports usage of signatureConfig.algorithm == NONE.
     * It checks inline mappings, function-local variables, and module-level variables.
     *
     * @param context the syntax node analysis context for reporting issues
     */
    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        analyzeImports(context);

        FunctionCallExpressionNode functionCall = (FunctionCallExpressionNode) context.node();

        if (!(functionCall.functionName() instanceof QualifiedNameReferenceNode qualifiedName)) {
            return;
        }

        String modulePrefix = qualifiedName.modulePrefix().text();
        String qualifiedNameText = qualifiedName.identifier().text();

        if (!jwtPrefixes.contains(modulePrefix) || !ISSUE.equals(qualifiedNameText)) {
            return;
        }

        for (FunctionArgumentNode arg : functionCall.arguments()) {
            ExpressionNode expr;
            switch (arg) {
                case PositionalArgumentNode posArg -> expr = posArg.expression();
                case NamedArgumentNode namedArg -> expr = namedArg.expression();
                default -> {
                    continue;
                }
            }
            if ((expr instanceof MappingConstructorExpressionNode mappingConstructor
                    && hasNoneAlgorithmInMappingLiteral(mappingConstructor))
                    || (expr instanceof SimpleNameReferenceNode varRef
                    && hasNoneAlgorithmInVariableReference(varRef))) {
                reporter.reportIssue(
                        getDocument(context.currentPackage().module(context.moduleId()), context.documentId()),
                        context.node().location(),
                        JWTRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId()
                );
            }
        }
    }

    /**
     * Checks if a variable reference is used in a function body or module member.
     *
     * @param varRef the variable reference node
     * @return true if the variable reference is used in a function body or module member, false otherwise
     */
    private boolean hasNoneAlgorithmInVariableReference(SimpleNameReferenceNode varRef) {
        String varName = varRef.name().text();
        Node current = varRef.parent();

        while (current != null) {
            if (current instanceof FunctionBodyBlockNode body
                    && hasWeakAlgorithmInStatements(body.statements(), varName)) {
                return true;
            }
            if (current instanceof ModulePartNode module
                    && hasWeakAlgorithmInModuleMembers(module.members(), varName)) {
                return true;
            }
            current = current.parent();
        }
        return false;
    }

    /**
     * Checks if a variable declaration contains a weak algorithm in its initializer.
     *
     * @param statements the list of statements in the function body
     * @param varName    the variable name to check
     * @return true if the variable declaration contains a weak algorithm, false otherwise
     */
    private boolean hasWeakAlgorithmInStatements(NodeList<StatementNode> statements, String varName) {
        for (StatementNode stmt : statements) {
            if (stmt instanceof VariableDeclarationNode varDecl
                    && isWeakAlgorithmInVarDecl(varDecl, varName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a module member declaration contains a weak algorithm in its initializer.
     *
     * @param members the list of module member declarations
     * @param varName the variable name to check
     * @return true if the module member declaration contains a weak algorithm, false otherwise
     */
    private boolean hasWeakAlgorithmInModuleMembers(NodeList<ModuleMemberDeclarationNode> members, String varName) {
        for (ModuleMemberDeclarationNode member : members) {
            if (member instanceof ModuleVariableDeclarationNode varDecl
                    && isWeakAlgorithmInVarDecl(varDecl, varName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a variable declaration contains a weak algorithm in its initializer.
     *
     * @param varDecl the variable declaration node
     * @param varName the variable name to check
     * @return true if the variable declaration contains a weak algorithm, false otherwise
     */
    private boolean isWeakAlgorithmInVarDecl(VariableDeclarationNode varDecl, String varName) {
        if (varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode capture
                && capture.variableName().text().equals(varName)
                && varDecl.initializer().isPresent()
                && varDecl.initializer().get() instanceof MappingConstructorExpressionNode mapping
                && hasNoneAlgorithmInMappingLiteral(mapping)) {
            return true;
        }
        return varDecl.typedBindingPattern().bindingPattern() instanceof ListBindingPatternNode listBinding
                && listBinding.bindingPatterns().get(0) instanceof CaptureBindingPatternNode capture
                && capture.variableName().text().equals(varName)
                && varDecl.initializer().isPresent()
                && varDecl.initializer().get() instanceof ListConstructorExpressionNode listConstructor
                && listConstructor.expressions().get(0) instanceof MappingConstructorExpressionNode mapping
                && hasNoneAlgorithmInMappingLiteral(mapping);
    }

    /**
     * Checks if a module variable declaration contains a weak algorithm in its initializer.
     *
     * @param varDecl the module variable declaration node
     * @param varName the variable name to check
     * @return true if the module variable declaration contains a weak algorithm, false otherwise
     */
    private boolean isWeakAlgorithmInVarDecl(ModuleVariableDeclarationNode varDecl, String varName) {
        if (varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode capture
                && capture.variableName().text().equals(varName)
                && varDecl.initializer().isPresent()
                && varDecl.initializer().get() instanceof MappingConstructorExpressionNode mapping
                && hasNoneAlgorithmInMappingLiteral(mapping)) {
            return true;
        }
        return varDecl.typedBindingPattern().bindingPattern() instanceof ListBindingPatternNode listBinding
                && listBinding.bindingPatterns().get(0) instanceof CaptureBindingPatternNode capture
                && capture.variableName().text().equals(varName)
                && varDecl.initializer().isPresent()
                && varDecl.initializer().get() instanceof ListConstructorExpressionNode listConstructor
                && listConstructor.expressions().get(0) instanceof MappingConstructorExpressionNode mapping
                && hasNoneAlgorithmInMappingLiteral(mapping);
    }

    /**
     * Inspects a mapping constructor expression for signatureConfig.algorithm == NONE.
     *
     * @param mappingConstructor the mapping constructor expression node
     * @return true if the inline mapping specifies algorithm NONE, false otherwise
     */
    private boolean hasNoneAlgorithmInMappingLiteral(MappingConstructorExpressionNode mappingConstructor) {
        for (MappingFieldNode field : mappingConstructor.fields()) {
            if (field instanceof SpecificFieldNode spec
                    && spec.fieldName().toString().contains(SIGNATURE_CONFIG)
                    && spec.valueExpr().isPresent()
                    && spec.valueExpr().get()
                    instanceof MappingConstructorExpressionNode mappingConstructorExpression) {
                for (MappingFieldNode nestedField : mappingConstructorExpression.fields()) {
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
    private static Document getDocument(Module module, DocumentId documentId) {
        return module.document(documentId);
    }

    /**
     * Analyzes imports to identify all prefixes used for the crypto module.
     *
     * @param context the syntax node analysis context
     */
    private void analyzeImports(SyntaxNodeAnalysisContext context) {
        Document document = getDocument(context.currentPackage().module(context.moduleId()), context.documentId());

        if (document.syntaxTree().rootNode() instanceof ModulePartNode modulePartNode) {
            modulePartNode.imports().forEach(importDeclarationNode -> {
                ImportOrgNameNode importOrgNameNode = importDeclarationNode.orgName().orElse(null);

                if (importOrgNameNode != null && BALLERINA_ORG.equals(importOrgNameNode.orgName().text())
                        && importDeclarationNode.moduleName().stream()
                        .anyMatch(moduleNameNode -> JWT.equals(moduleNameNode.text()))) {

                    ImportPrefixNode importPrefixNode = importDeclarationNode.prefix().orElse(null);
                    String prefix = importPrefixNode != null ? importPrefixNode.prefix().text() : JWT;

                    jwtPrefixes.add(prefix);
                }
            });
        }
    }
}
