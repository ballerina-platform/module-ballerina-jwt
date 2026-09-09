/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.ballerina.projects.Project;
import io.ballerina.projects.ProjectEnvironmentBuilder;
import io.ballerina.projects.directory.BuildProject;
import io.ballerina.projects.environment.Environment;
import io.ballerina.projects.environment.EnvironmentBuilder;
import io.ballerina.scan.Issue;
import io.ballerina.scan.Rule;
import io.ballerina.scan.Source;
import io.ballerina.scan.test.Assertions;
import io.ballerina.scan.test.TestOptions;
import io.ballerina.scan.test.TestRunner;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import static io.ballerina.scan.RuleKind.VULNERABILITY;
import static java.nio.charset.StandardCharsets.UTF_8;

public class StaticCodeAnalyzerTest {
    private static final Path RESOURCE_PACKAGES_DIRECTORY = Paths
            .get("src", "test", "resources", "static_code_analyzer", "ballerina_packages").toAbsolutePath();
    private static final Path EXPECTED_OUTPUT_DIRECTORY = Paths
            .get("src", "test", "resources", "static_code_analyzer", "expected_output").toAbsolutePath();
    private static final Path JSON_RULES_FILE_PATH = Paths
            .get("../", "compiler-plugin", "src", "main", "resources", "rules.json").toAbsolutePath();
    private static final Path DISTRIBUTION_PATH = Paths.get("../", "target", "ballerina-runtime");
    private static final String MODULE_BALLERINA_JWT = "module-ballerina-jwt";
    private static final String START_OFFSET_FIELD = "startOffset";
    private static final List<String> BYTE_OFFSET_FIELDS = List.of(START_OFFSET_FIELD, "length");

    @Test
    public void validateRulesJson() throws IOException {
        String expectedRules = "[" + Arrays.stream(JwtRule.values())
                .map(JwtRule::toString).collect(Collectors.joining(",")) + "]";
        String actualRules = Files.readString(JSON_RULES_FILE_PATH);
        assertJsonEqual(actualRules, expectedRules);
    }

    @Test
    public void testStaticCodeRulesWithAPI() throws IOException {
        ByteArrayOutputStream console = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(console, true, UTF_8);

        for (JwtRule rule : JwtRule.values()) {
            testIndividualRule(rule, console, printStream);
        }
    }

    private void testIndividualRule(JwtRule rule, ByteArrayOutputStream console, PrintStream printStream)
            throws IOException {
        String targetPackageName = "rule" + rule.getId();
        Path targetPackagePath = RESOURCE_PACKAGES_DIRECTORY.resolve(targetPackageName);

        TestRunner testRunner = setupTestRunner(targetPackagePath, printStream);
        testRunner.performScan();

        validateRules(testRunner.getRules());
        validateIssues(rule, testRunner.getIssues());
        validateOutput(console, targetPackageName);

        console.reset();
    }

    private TestRunner setupTestRunner(Path targetPackagePath, PrintStream printStream) {
        Project project = BuildProject.load(getEnvironmentBuilder(), targetPackagePath);
        TestOptions options = TestOptions.builder(project).setOutputStream(printStream).build();
        return new TestRunner(options);
    }

    private void validateRules(List<Rule> rules) {
        for (JwtRule rule : JwtRule.values()) {
            Assertions.assertRule(rules, "ballerina/jwt:" + rule.getId(), rule.getDescription(), VULNERABILITY);
        }
    }

    private void validateIssues(JwtRule rule, List<Issue> issues) {
        int index;
        switch (rule) {
            case AVOID_WEAK_CIPHER_ALGORITHMS:
                index = 0;
                Assert.assertEquals(issues.size(), 14);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "constant_reference_algorithm.bal",
                        23, 29, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "constant_reference_algorithm.bal",
                        34, 40, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "function_named_arg_capture_pattern.bal",
                        27, 27, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "function_named_arg_list_pattern.bal",
                        29, 29, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "function_pos_arg_capture_pattern.bal",
                        27, 27, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "function_pos_arg_list_pattern.bal",
                        29, 29, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "inline_named_arg.bal",
                        19, 25, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "inline_pos_arg.bal",
                        19, 25, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "module_named_arg_capture_pattern.bal",
                        27, 27, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "module_named_arg_list_pattern.bal",
                        29, 29, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "module_pos_arg_capture_pattern.bal",
                        27, 27, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "module_pos_arg_list_pattern.bal",
                        29, 29, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:1", "string_literal_algorithm.bal",
                        19, 24, Source.BUILT_IN);
                Assertions.assertIssue(issues, index, "ballerina/jwt:1", "string_literal_algorithm.bal",
                        27, 32, Source.BUILT_IN);
                break;
            case ENSURE_SIGNATURE_VERIFICATION:
                index = 0;
                Assert.assertEquals(issues.size(), 3);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:2", "no_signature_config.bal",
                        20, 23, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:2", "no_signature_config.bal",
                        33, 33, Source.BUILT_IN);
                Assertions.assertIssue(issues, index, "ballerina/jwt:2", "no_signature_config.bal",
                        49, 49, Source.BUILT_IN);
                break;
            case ENSURE_ISSUER_AND_AUDIENCE_VALIDATION:
                index = 0;
                Assert.assertEquals(issues.size(), 2);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:3", "no_issuer_or_audience.bal",
                        20, 25, Source.BUILT_IN);
                Assertions.assertIssue(issues, index, "ballerina/jwt:3", "no_issuer_or_audience.bal",
                        30, 35, Source.BUILT_IN);
                break;
            case AVOID_LONG_TOKEN_EXPIRY:
                index = 0;
                Assert.assertEquals(issues.size(), 5);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:4", "long_expiry.bal",
                        23, 23, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:4", "long_expiry.bal",
                        37, 37, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:4", "long_expiry.bal",
                        70, 70, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:4", "long_expiry.bal",
                        87, 87, Source.BUILT_IN);
                Assertions.assertIssue(issues, index, "ballerina/jwt:4", "shadowed_config.bal",
                        21, 21, Source.BUILT_IN);
                break;
            case AVOID_LARGE_CLOCK_SKEW:
                index = 0;
                Assert.assertEquals(issues.size(), 3);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:5", "large_clock_skew.bal",
                        23, 23, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:5", "large_clock_skew.bal",
                        58, 58, Source.BUILT_IN);
                Assertions.assertIssue(issues, index, "ballerina/jwt:5", "large_clock_skew.bal",
                        72, 72, Source.BUILT_IN);
                break;
            case AVOID_DISABLED_JWKS_TLS:
                index = 0;
                Assert.assertEquals(issues.size(), 3);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:6", "jwks_tls_disabled.bal",
                        28, 28, Source.BUILT_IN);
                Assertions.assertIssue(issues, index++, "ballerina/jwt:6", "jwks_tls_disabled.bal",
                        57, 57, Source.BUILT_IN);
                Assertions.assertIssue(issues, index, "ballerina/jwt:6", "jwks_tls_disabled.bal",
                        87, 87, Source.BUILT_IN);
                break;
            case AVOID_UNVERIFIED_TOKEN_DECODING:
                index = 0;
                Assert.assertEquals(issues.size(), 1);
                Assertions.assertIssue(issues, index, "ballerina/jwt:7", "unverified_decode.bal",
                        20, 20, Source.BUILT_IN);
                break;
            default:
                Assert.fail("Unhandled rule in validateIssues: " + rule);
                break;
        }
    }

    private void validateOutput(ByteArrayOutputStream console, String targetPackageName) throws IOException {
        String output = console.toString(UTF_8);
        String jsonOutput = extractJson(output);
        String expectedOutput = Files.readString(EXPECTED_OUTPUT_DIRECTORY.resolve(targetPackageName + ".json"));
        assertJsonEqual(jsonOutput, expectedOutput);
    }

    private static ProjectEnvironmentBuilder getEnvironmentBuilder() {
        Environment environment = EnvironmentBuilder.getBuilder().setBallerinaHome(DISTRIBUTION_PATH).build();
        return ProjectEnvironmentBuilder.getBuilder(environment);
    }

    private String extractJson(String consoleOutput) {
        int startIndex = consoleOutput.indexOf("[");
        int endIndex = consoleOutput.lastIndexOf("]");
        if (startIndex == -1 || endIndex == -1) {
            return "";
        }
        return consoleOutput.substring(startIndex, endIndex + 1);
    }

    private void assertJsonEqual(String actual, String expected) {
        Assert.assertEquals(normalizeString(actual), normalizeString(expected));
    }

    private static String normalizeString(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
            JsonNode node = mapper.readTree(json);
            // The byte offsets shift with the line endings the fixtures were checked out with
            node.findParents(START_OFFSET_FIELD)
                    .forEach(location -> ((ObjectNode) location).remove(BYTE_OFFSET_FIELDS));
            String normalizedJson = mapper.writeValueAsString(node)
                    .replaceAll(":\"[^\"]*" + MODULE_BALLERINA_JWT, ":\"" + MODULE_BALLERINA_JWT);
            return isWindows() ? normalizedJson.replace("/", "\\\\") : normalizedJson;
        } catch (Exception ignore) {
            return json;
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ENGLISH).startsWith("windows");
    }
}
