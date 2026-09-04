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

import io.ballerina.compiler.syntax.tree.AssignmentStatementNode;
import io.ballerina.compiler.syntax.tree.BasicLiteralNode;
import io.ballerina.compiler.syntax.tree.BlockStatementNode;
import io.ballerina.compiler.syntax.tree.CaptureBindingPatternNode;
import io.ballerina.compiler.syntax.tree.CheckExpressionNode;
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
import io.ballerina.compiler.syntax.tree.TypeCastExpressionNode;
import io.ballerina.compiler.syntax.tree.TypedBindingPatternNode;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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
     * The record is written either inline at the call site or in a variable declared in an enclosing block or at
     * module level. A variable assigned anything other than a record literal cannot be resolved without data-flow
     * analysis and yields an empty result.
     * <p>
     * The blocks are searched innermost first, and within a block only declarations that precede the reference are
     * considered, so the declaration found is the one the reference actually binds to rather than a later
     * same-named local.
     *
     * @param expression the argument expression
     * @return the configuration record if it can be resolved, empty otherwise
     */
    public static Optional<MappingConstructorExpressionNode> resolveConfigRecord(ExpressionNode expression) {
        return resolveConfigRecord(expression, List.of());
    }

    /**
     * Resolve the configuration record behind an argument, falling back to the module's other documents.
     * <p>
     * A configuration declared in a sibling {@code .bal} file is as much a module-level declaration as one in the
     * same file, so a lookup confined to the current document would silently skip every configuration rule for it.
     *
     * @param expression        the argument expression
     * @param siblingModuleParts the module's other documents
     * @return the configuration record if it can be resolved, empty otherwise
     */
    public static Optional<MappingConstructorExpressionNode> resolveConfigRecord(
            ExpressionNode expression, List<ModulePartNode> siblingModuleParts) {
        if (expression instanceof MappingConstructorExpressionNode mappingConstructor) {
            return Optional.of(mappingConstructor);
        }
        if (!(expression instanceof SimpleNameReferenceNode variableReference)) {
            return Optional.empty();
        }
        String variableName = variableReference.name().text();
        int referenceOffset = variableReference.textRange().startOffset();
        Node current = variableReference.parent();
        while (current != null) {
            Optional<MappingConstructorExpressionNode> resolved = switch (current) {
                case BlockStatementNode block ->
                        findInStatements(block.statements(), variableName, referenceOffset);
                case FunctionBodyBlockNode body ->
                        findInStatements(body.statements(), variableName, referenceOffset);
                case ModulePartNode modulePart -> findInModuleMembers(modulePart.members(), variableName);
                default -> Optional.empty();
            };
            if (resolved.isPresent()) {
                return resolved;
            }
            current = current.parent();
        }
        for (ModulePartNode siblingModulePart : siblingModuleParts) {
            Optional<MappingConstructorExpressionNode> resolved =
                    findInModuleMembers(siblingModulePart.members(), variableName);
            if (resolved.isPresent()) {
                return resolved;
            }
        }
        return Optional.empty();
    }

    private static Optional<MappingConstructorExpressionNode> findInStatements(NodeList<StatementNode> statements,
                                                                              String variableName,
                                                                              int referenceOffset) {
        Optional<MappingConstructorExpressionNode> resolved = Optional.empty();
        for (StatementNode statement : statements) {
            if (statement.textRange().endOffset() > referenceOffset) {
                break;
            }
            if (statement instanceof VariableDeclarationNode variableDeclaration) {
                Optional<MappingConstructorExpressionNode> candidate = matchDeclaration(
                        variableDeclaration.typedBindingPattern(), variableDeclaration.initializer(), variableName);
                if (candidate.isPresent()) {
                    resolved = candidate;
                }
            } else if (statement instanceof AssignmentStatementNode assignment
                    && variableName.equals(assignment.varRef().toSourceCode().trim())) {
                // A later assignment replaces the record the declaration set, so the earlier one is no longer
                // what the call receives. An assignment of anything but a record literal leaves it unresolved.
                resolved = Optional.of(getEffectiveExpression(assignment.expression()))
                        .filter(MappingConstructorExpressionNode.class::isInstance)
                        .map(MappingConstructorExpressionNode.class::cast);
            }
        }
        return resolved;
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
        List<ExpressionNode> positionalArguments = new ArrayList<>();
        for (FunctionArgumentNode argument : functionCall.arguments()) {
            switch (argument) {
                case NamedArgumentNode namedArgument
                        when parameterName.equals(namedArgument.argumentName().name().text()) -> {
                    return Optional.of(namedArgument.expression());
                }
                case PositionalArgumentNode positionalArgument ->
                        positionalArguments.add(positionalArgument.expression());
                default -> {
                    // A rest argument spreads a value that cannot be resolved without data-flow analysis
                }
            }
        }
        return position < positionalArguments.size() ? Optional.of(positionalArguments.get(position))
                : Optional.empty();
    }

    /**
     * Find a field by name within a configuration record. Computed and spread fields cannot be resolved statically
     * and are skipped.
     *
     * @param configRecord the configuration record
     * @param fieldName    the field name to look for
     * @return the matching field if present, empty otherwise
     */
    public static Optional<SpecificFieldNode> findField(MappingConstructorExpressionNode configRecord,
                                                        String fieldName) {
        return configRecord.fields().stream()
                .filter(field -> field.kind() == SyntaxKind.SPECIFIC_FIELD)
                .map(field -> (SpecificFieldNode) field)
                .filter(field -> matchesFieldName(field.fieldName(), fieldName))
                .findFirst();
    }

    /**
     * Unwrap a {@code check} or a type cast to reach the expression underneath.
     */
    private static ExpressionNode getEffectiveExpression(ExpressionNode expression) {
        return switch (expression) {
            case CheckExpressionNode checkExpression -> checkExpression.expression();
            case TypeCastExpressionNode castExpression -> castExpression.expression();
            default -> expression;
        };
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
     * Get a field whose value is itself a record, written inline or held in a variable.
     *
     * @param configRecord the configuration record
     * @param fieldName    the field name to look for
     * @return the nested record if present, empty otherwise
     */
    public static Optional<MappingConstructorExpressionNode> getNestedRecord(
            MappingConstructorExpressionNode configRecord, String fieldName) {
        return findField(configRecord, fieldName)
                .flatMap(SpecificFieldNode::valueExpr)
                .flatMap(JwtAnalysisUtils::resolveConfigRecord);
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
     * written with a fraction, as a negated literal, or with the {@code d} suffix that spells the type out.
     *
     * @param expression the expression to read
     * @return the literal value if the expression is a numeric literal, empty otherwise
     */
    public static Optional<BigDecimal> getNumericLiteralValue(ExpressionNode expression) {
        String source = expression.toSourceCode().trim();
        if (source.endsWith("d") || source.endsWith("D")) {
            source = source.substring(0, source.length() - 1);
        }
        try {
            return Optional.of(new BigDecimal(source));
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
