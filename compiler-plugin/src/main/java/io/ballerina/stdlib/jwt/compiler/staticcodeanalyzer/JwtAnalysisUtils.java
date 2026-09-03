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

import io.ballerina.compiler.syntax.tree.BasicLiteralNode;
import io.ballerina.compiler.syntax.tree.CaptureBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionArgumentNode;
import io.ballerina.compiler.syntax.tree.FunctionBodyBlockNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.IdentifierToken;
import io.ballerina.compiler.syntax.tree.ImportDeclarationNode;
import io.ballerina.compiler.syntax.tree.ImportOrgNameNode;
import io.ballerina.compiler.syntax.tree.ListBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ListConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingConstructorExpressionNode;
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
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.compiler.syntax.tree.TypedBindingPatternNode;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;

import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Shared helpers for the JWT static code analysis rules.
 * <p>
 * The JWT configuration records are supplied to {@code jwt:issue} and {@code jwt:validate} either inline or through a
 * variable, so every rule needs the same two things: the configuration record behind an argument, and a way to read a
 * literal field out of it.
 *
 * @since 2.16.0
 */
public final class JwtAnalysisUtils {

    private static final String JWT = "jwt";
    private static final String BALLERINA_ORG = "ballerina";

    private JwtAnalysisUtils() {
    }

    /**
     * Resolve the configuration record behind an argument expression.
     * <p>
     * The record is written either inline at the call site or in a variable declared in the enclosing function or at
     * module level. A variable assigned anything other than a record literal cannot be resolved without data-flow
     * analysis and yields an empty result.
     *
     * @param expression the argument expression
     * @return the configuration record if it can be resolved, empty otherwise
     */
    public static Optional<MappingConstructorExpressionNode> resolveConfigRecord(ExpressionNode expression) {
        if (expression instanceof MappingConstructorExpressionNode mappingConstructor) {
            return Optional.of(mappingConstructor);
        }
        if (!(expression instanceof SimpleNameReferenceNode variableReference)) {
            return Optional.empty();
        }
        String variableName = variableReference.name().text();
        Node current = variableReference.parent();
        while (current != null) {
            Optional<MappingConstructorExpressionNode> resolved = switch (current) {
                case FunctionBodyBlockNode body -> findInStatements(body.statements(), variableName);
                case ModulePartNode modulePart -> findInModuleMembers(modulePart.members(), variableName);
                default -> Optional.empty();
            };
            if (resolved.isPresent()) {
                return resolved;
            }
            current = current.parent();
        }
        return Optional.empty();
    }

    private static Optional<MappingConstructorExpressionNode> findInStatements(NodeList<StatementNode> statements,
                                                                              String variableName) {
        for (StatementNode statement : statements) {
            if (statement instanceof VariableDeclarationNode variableDeclaration) {
                Optional<MappingConstructorExpressionNode> resolved = matchDeclaration(
                        variableDeclaration.typedBindingPattern(), variableDeclaration.initializer(), variableName);
                if (resolved.isPresent()) {
                    return resolved;
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<MappingConstructorExpressionNode> findInModuleMembers(
            NodeList<ModuleMemberDeclarationNode> members, String variableName) {
        for (ModuleMemberDeclarationNode member : members) {
            if (member instanceof ModuleVariableDeclarationNode variableDeclaration) {
                Optional<MappingConstructorExpressionNode> resolved = matchDeclaration(
                        variableDeclaration.typedBindingPattern(), variableDeclaration.initializer(), variableName);
                if (resolved.isPresent()) {
                    return resolved;
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Match a declaration against the wanted variable name and return the record it was initialised with.
     * <p>
     * A tuple destructuring binds several names at once, so the record is taken from the position the name occupies
     * rather than from the first element.
     */
    private static Optional<MappingConstructorExpressionNode> matchDeclaration(TypedBindingPatternNode bindingPattern,
                                                                              Optional<ExpressionNode> initializer,
                                                                              String variableName) {
        if (initializer.isEmpty()) {
            return Optional.empty();
        }
        if (bindingPattern.bindingPattern() instanceof CaptureBindingPatternNode capture
                && capture.variableName().text().equals(variableName)
                && initializer.get() instanceof MappingConstructorExpressionNode mappingConstructor) {
            return Optional.of(mappingConstructor);
        }
        if (bindingPattern.bindingPattern() instanceof ListBindingPatternNode listBinding
                && initializer.get() instanceof ListConstructorExpressionNode listConstructor) {
            for (int position = 0; position < listBinding.bindingPatterns().size(); position++) {
                if (listBinding.bindingPatterns().get(position) instanceof CaptureBindingPatternNode capture
                        && capture.variableName().text().equals(variableName)
                        && position < listConstructor.expressions().size()
                        && listConstructor.expressions().get(position)
                        instanceof MappingConstructorExpressionNode mappingConstructor) {
                    return Optional.of(mappingConstructor);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Get an argument by position or by name, so a rule reads the same value whichever form the caller used.
     *
     * @param functionCall  the call to read
     * @param position      the zero-based position of the parameter
     * @param parameterName the parameter's name
     * @return the argument expression if supplied, empty otherwise
     */
    public static Optional<ExpressionNode> getArgument(FunctionCallExpressionNode functionCall, int position,
                                                       String parameterName) {
        int positionalIndex = 0;
        for (FunctionArgumentNode argument : functionCall.arguments()) {
            switch (argument) {
                case NamedArgumentNode namedArgument -> {
                    if (parameterName.equals(namedArgument.argumentName().name().text())) {
                        return Optional.of(namedArgument.expression());
                    }
                }
                case PositionalArgumentNode positionalArgument -> {
                    if (positionalIndex++ == position) {
                        return Optional.of(positionalArgument.expression());
                    }
                }
                default -> {
                    // A rest argument spreads a value that cannot be resolved without data-flow analysis
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Find a field by name within a configuration record. Computed and spread fields cannot be resolved statically
     * and are skipped.
     *
     * @param record    the configuration record
     * @param fieldName the field name to look for
     * @return the matching field if present, empty otherwise
     */
    public static Optional<SpecificFieldNode> findField(MappingConstructorExpressionNode record, String fieldName) {
        return record.fields().stream()
                .filter(field -> field.kind() == SyntaxKind.SPECIFIC_FIELD)
                .map(field -> (SpecificFieldNode) field)
                .filter(field -> matchesFieldName(field.fieldName(), fieldName))
                .findFirst();
    }

    private static boolean matchesFieldName(Node fieldNameNode, String expectedFieldName) {
        if (fieldNameNode instanceof IdentifierToken identifierToken) {
            String fieldName = identifierToken.text();
            return fieldName.equals(expectedFieldName) || fieldName.equals("'" + expectedFieldName);
        }
        if (fieldNameNode instanceof BasicLiteralNode basicLiteralNode) {
            String literal = basicLiteralNode.literalToken().text();
            return literal.substring(1, literal.length() - 1).equals(expectedFieldName);
        }
        return false;
    }

    /**
     * Get a field whose value is itself a record.
     *
     * @param record    the configuration record
     * @param fieldName the field name to look for
     * @return the nested record if present, empty otherwise
     */
    public static Optional<MappingConstructorExpressionNode> getNestedRecord(MappingConstructorExpressionNode record,
                                                                            String fieldName) {
        return findField(record, fieldName)
                .flatMap(SpecificFieldNode::valueExpr)
                .filter(MappingConstructorExpressionNode.class::isInstance)
                .map(MappingConstructorExpressionNode.class::cast);
    }

    /**
     * Get the value of a boolean literal expression.
     * <p>
     * Only a literal is actionable. A variable or a computed expression cannot be resolved without data-flow
     * analysis, and reporting on one would be a guess.
     *
     * @param expression the expression to read
     * @return the literal value if the expression is a boolean literal, empty otherwise
     */
    public static Optional<Boolean> getBooleanLiteralValue(ExpressionNode expression) {
        String source = expression.toSourceCode().trim();
        if (Boolean.TRUE.toString().equals(source)) {
            return Optional.of(true);
        }
        if (Boolean.FALSE.toString().equals(source)) {
            return Optional.of(false);
        }
        return Optional.empty();
    }

    /**
     * Get the value of a numeric literal expression. The JWT durations are {@code decimal}, so a value may be
     * written with a fraction or as a negated literal.
     *
     * @param expression the expression to read
     * @return the literal value if the expression is a numeric literal, empty otherwise
     */
    public static Optional<BigDecimal> getNumericLiteralValue(ExpressionNode expression) {
        try {
            return Optional.of(new BigDecimal(expression.toSourceCode().trim()));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }


    /**
     * Collect every prefix the {@code ballerina/jwt} module is imported under in the document being analyzed.
     * <p>
     * The set is built per document rather than accumulated, since a prefix introduced by an alias in one file says
     * nothing about what that prefix means in another.
     *
     * @param context the syntax node analysis context
     * @return the prefixes the JWT module is reachable through in this document
     */
    public static Set<String> collectJwtPrefixes(SyntaxNodeAnalysisContext context) {
        Set<String> prefixes = new HashSet<>();
        if (!(getDocument(context).syntaxTree().rootNode() instanceof ModulePartNode modulePart)) {
            return prefixes;
        }
        for (ImportDeclarationNode importDeclaration : modulePart.imports()) {
            Optional<ImportOrgNameNode> orgName = importDeclaration.orgName();
            boolean isJwtImport = orgName.isPresent() && BALLERINA_ORG.equals(orgName.get().orgName().text())
                    && importDeclaration.moduleName().stream().anyMatch(name -> JWT.equals(name.text()));
            if (isJwtImport) {
                prefixes.add(importDeclaration.prefix()
                        .map(prefix -> prefix.prefix().text())
                        .orElse(JWT));
            }
        }
        return prefixes;
    }

    /**
     * Get the name of the JWT module function being called, if the call targets the JWT module at all.
     *
     * @param functionCall the call to inspect
     * @param jwtPrefixes  the prefixes the JWT module is reachable through
     * @return the function's simple name if the call targets the JWT module, empty otherwise
     */
    public static Optional<String> getJwtFunctionName(FunctionCallExpressionNode functionCall,
                                                      Set<String> jwtPrefixes) {
        if (!(functionCall.functionName() instanceof QualifiedNameReferenceNode qualifiedName)) {
            return Optional.empty();
        }
        if (!jwtPrefixes.contains(qualifiedName.modulePrefix().text())) {
            return Optional.empty();
        }
        return Optional.of(qualifiedName.identifier().text());
    }

    /**
     * Retrieve the document being analyzed.
     *
     * @param context the syntax node analysis context
     * @return the document the analyzed node belongs to
     */
    public static Document getDocument(SyntaxNodeAnalysisContext context) {
        Module module = context.currentPackage().module(context.moduleId());
        DocumentId documentId = context.documentId();
        return module.document(documentId);
    }
}
