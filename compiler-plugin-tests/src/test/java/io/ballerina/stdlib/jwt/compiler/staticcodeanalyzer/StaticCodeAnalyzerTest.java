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

import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;
import org.testng.internal.ExitCode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This class includes tests for Ballerina Http static code analyzer.
 *
 * @since 2.15.1
 */
public class StaticCodeAnalyzerTest {
    private static final Path RESOURCE_PACKAGES_DIRECTORY = Paths
            .get("src", "test", "resources", "static_code_analyzer", "ballerina_packages").toAbsolutePath();
    private static final Path EXPECTED_JSON_OUTPUT_DIRECTORY = Paths.
            get("src", "test", "resources", "static_code_analyzer", "expected_output").toAbsolutePath();
    private static final Path BALLERINA_PATH = getBalCommandPath();
    private static final Path JSON_RULES_FILE_PATH = Paths
            .get("../", "compiler-plugin", "src", "main", "resources", "rules.json").toAbsolutePath();
    private static final String SCAN_COMMAND = "scan";

    private static Path getBalCommandPath() {
        String balCommand = isWindows() ? "bal.bat" : "bal";
        return Paths.get("../", "target", "ballerina-runtime", "bin", balCommand).toAbsolutePath();
    }

    @BeforeSuite
    public void pullScanTool() throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(BALLERINA_PATH.toString(), "tool", "pull", SCAN_COMMAND);
        ProcessOutputGobbler output = getOutput(processBuilder.start()).join();
        if (Pattern.compile("tool 'scan:.+\\..+\\..+' successfully set as the active version\\.")
                .matcher(output.getOutput()).find() || Pattern.compile("tool 'scan:.+\\..+\\..+' is already active\\.")
                .matcher(output.getOutput()).find()) {
            return;
        }
        Assert.assertFalse(ExitCode.hasFailure(output.getExitCode()));
    }

    @Test
    public void validateRulesJson() throws IOException {
        String expectedRules = "[" + Arrays.stream(JWTRule.values())
                .map(JWTRule::toString).collect(Collectors.joining(",")) + "]";
        String actualRules = Files.readString(JSON_RULES_FILE_PATH);
        assertJsonEqual(normalizeJson(actualRules), normalizeJson(expectedRules));
    }

    @Test
    public void testStaticCodeRules() throws IOException {
        for (JWTRule rule : JWTRule.values()) {
            String targetPackageName = "rule" + rule.getId();
            String actualJsonReport = StaticCodeAnalyzerTest.executeScanProcess(targetPackageName);
            String expectedJsonReport = Files
                    .readString(EXPECTED_JSON_OUTPUT_DIRECTORY.resolve(targetPackageName + ".json"));
            assertJsonEqual(actualJsonReport, expectedJsonReport);
        }
    }

    private static String executeScanProcess(String targetPackage) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(BALLERINA_PATH.toString(), SCAN_COMMAND);
        processBuilder.directory(RESOURCE_PACKAGES_DIRECTORY.resolve(targetPackage).toFile());
        ProcessOutputGobbler output = getOutput(processBuilder.start()).join();
        Assert.assertFalse(ExitCode.hasFailure(output.getExitCode()));
        return Files.readString(RESOURCE_PACKAGES_DIRECTORY.resolve(targetPackage)
                .resolve("target").resolve("report").resolve("scan_results.json"));
    }

    private static CompletableFuture<ProcessOutputGobbler> getOutput(Process process) {
        ProcessOutputGobbler outputGobbler = new ProcessOutputGobbler(process.getInputStream());
        ProcessOutputGobbler errorGobbler = new ProcessOutputGobbler(process.getErrorStream());
        Thread outputThread = new Thread(outputGobbler);
        Thread errorThread = new Thread(errorGobbler);
        outputThread.start();
        errorThread.start();

        return CompletableFuture.supplyAsync(() -> {
            try {
                int exitCode = process.waitFor();
                outputGobbler.setExitCode(exitCode);
                errorGobbler.setExitCode(exitCode);
                outputThread.join();
                errorThread.join();
                return outputGobbler;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });
    }

    private void assertJsonEqual(String actual, String expected) {
        Assert.assertEquals(normalizeJson(actual), normalizeJson(expected));
    }

    private static String normalizeJson(String json) {
        String normalizedJson = json.replaceAll("\\s*\"\\s*", "\"")
                .replaceAll("\\s*:\\s*", ":")
                .replaceAll("\\s*,\\s*", ",")
                .replaceAll("\\s*\\{\\s*", "{")
                .replaceAll("\\s*}\\s*", "}")
                .replaceAll("\\s*\\[\\s*", "[")
                .replaceAll("\\s*]\\s*", "]")
                .replaceAll("\n", "")
                .replaceAll(":\".*module-ballerina-jwt", ":\"module-ballerina-jwt");
        return isWindows() ? normalizedJson.replaceAll("/", "\\\\\\\\") : normalizedJson;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ENGLISH).startsWith("windows");
    }
}
