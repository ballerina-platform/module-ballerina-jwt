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

import io.ballerina.projects.Project;
import io.ballerina.projects.ProjectEnvironmentBuilder;
import io.ballerina.projects.directory.BuildProject;
import io.ballerina.projects.environment.Environment;
import io.ballerina.projects.environment.EnvironmentBuilder;
import io.ballerina.scan.Issue;
import io.ballerina.scan.Rule;
import io.ballerina.scan.RuleKind;
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

import static io.ballerina.stdlib.jwt.compiler.staticcodeanalyzer.JWTRule.AVOID_WEAK_CIPHER_ALGORITHMS;

public class StaticCodeAnalyzerTest {
    private static final Path RESOURCE_PACKAGES_DIRECTORY = Paths
            .get("src", "test", "resources", "static_code_analyzer", "ballerina_packages").toAbsolutePath();
    private static final Path EXPECTED_OUTPUT_DIRECTORY = Paths
            .get("src", "test", "resources", "static_code_analyzer", "expected_output").toAbsolutePath();
    private static final Path JSON_RULES_FILE_PATH = Paths
            .get("../", "compiler-plugin", "src", "main", "resources", "rules.json").toAbsolutePath();
    private static final Path DISTRIBUTION_PATH = Paths.get("../", "target", "ballerina-runtime");
    private static final String MODULE_BALLERINA_JWT = "module-ballerina-jwt";

    @Test
    public void validateRulesJson() throws IOException {
        String expectedRules = "[" + Arrays.stream(JWTRule.values())
                .map(JWTRule::toString).collect(Collectors.joining(",")) + "]";
        String actualRules = Files.readString(JSON_RULES_FILE_PATH);
        assertJsonEqual(actualRules, expectedRules);
    }

    @Test
    public void testStaticCodeRulesWithAPI() throws IOException {
        ByteArrayOutputStream console = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(console);
        for (JWTRule rule : JWTRule.values()) {
            String targetPackageName = "rule" + rule.getId();
            Path targetPackagePath = RESOURCE_PACKAGES_DIRECTORY.resolve(targetPackageName);
            Project project = BuildProject.load(getEnvironmentBuilder(), targetPackagePath);
            TestOptions options = TestOptions.builder(project)
                    .setOutputStream(printStream)
                    .build();
            TestRunner testRunner = new TestRunner(options);
            testRunner.performScan();

            // validate the rules
            List<Rule> rules = testRunner.getRules();
            Assertions.assertRule(
                    rules,
                    "ballerina/jwt:1",
                    "Avoid using weak cipher algorithms when signing and verifying JWTs",
                    RuleKind.VULNERABILITY);

            // validate the issues
            List<Issue> issues = testRunner.getIssues();
            int index = 0;
            if (rule == AVOID_WEAK_CIPHER_ALGORITHMS) {
                Assert.assertEquals(issues.size(), 10);
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
                Assertions.assertIssue(issues, index, "ballerina/jwt:1", "module_pos_arg_list_pattern.bal",
                        29, 29, Source.BUILT_IN);
            }

            // validate the output
            String output = console.toString();
            String jsonOutput = extractJson(output);
            String expectedOutput = Files.readString(EXPECTED_OUTPUT_DIRECTORY.resolve(targetPackageName
                    + ".json"));
            assertJsonEqual(jsonOutput, expectedOutput);
        }
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
        String normalizedJson = json.replaceAll("\\s*\"\\s*", "\"")
                .replaceAll("\\s*:\\s*", ":")
                .replaceAll("\\s*,\\s*", ",")
                .replaceAll("\\s*\\{\\s*", "{")
                .replaceAll("\\s*}\\s*", "}")
                .replaceAll("\\s*\\[\\s*", "[")
                .replaceAll("\\s*]\\s*", "]")
                .replaceAll("\n", "")
                .replaceAll(":\".*" + MODULE_BALLERINA_JWT, ":\"" + MODULE_BALLERINA_JWT);
        return isWindows() ? normalizedJson.replaceAll("/", "\\\\\\\\") : normalizedJson;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ENGLISH).startsWith("windows");
    }
}
