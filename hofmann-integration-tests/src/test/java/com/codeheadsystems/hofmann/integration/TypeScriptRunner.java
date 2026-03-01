package com.codeheadsystems.hofmann.integration;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility to invoke TypeScript cross-client tests via Node.js / npm.
 * Runs the cross-client vitest suite in the hofmann-typescript directory
 * and communicates results via files in a shared output directory.
 */
final class TypeScriptRunner {

  private static final Logger log = LoggerFactory.getLogger(TypeScriptRunner.class);
  private static final long TIMEOUT_SECONDS = 120;

  private TypeScriptRunner() {
  }

  /**
   * Checks whether the TypeScript module is available (node_modules installed and dist built).
   * Cross-client tests are skipped when TS is not available.
   */
  static boolean isTypeScriptAvailable() {
    Path tsDir = findTypeScriptDir();
    return tsDir != null
        && Files.isDirectory(tsDir.resolve("node_modules"))
        && Files.isDirectory(tsDir.resolve("dist"));
  }

  /**
   * Runs the cross-client test suite in hofmann-typescript with the given server URL
   * and output directory.
   *
   * @param serverUrl the base URL of the running Spring Boot server (e.g. http://localhost:8080)
   * @param outputDir the directory where TS writes result files
   * @param testFilter vitest test name filter (e.g. "cross-client OPRF")
   * @return the process exit code (0 = success)
   */
  static int runCrossClientTest(String serverUrl, Path outputDir, String testFilter)
      throws IOException, InterruptedException {
    Path tsDir = findTypeScriptDir();
    if (tsDir == null) {
      throw new IllegalStateException("Cannot find hofmann-typescript directory");
    }

    Files.createDirectories(outputDir);
    // Clean only TS-written result files to avoid stale data from previous runs.
    // Java-written input files (e.g. opaque-java-registered-*.txt) are preserved.
    for (String tsFile : new String[]{"oprf-ts.txt", "opaque-ts-auth-result.txt", "opaque-ts-reg-result.txt"}) {
      Files.deleteIfExists(outputDir.resolve(tsFile));
    }

    var command = new java.util.ArrayList<>(java.util.List.of(
        "npx", "vitest", "run", "cross-client", "--reporter=verbose"));
    if (testFilter != null && !testFilter.isEmpty()) {
      command.add("--testNamePattern");
      command.add(testFilter);
    }

    ProcessBuilder pb = new ProcessBuilder(command)
        .directory(tsDir.toFile())
        .redirectErrorStream(true);

    pb.environment().put("TEST_SERVER_URL", serverUrl);
    pb.environment().put("TEST_OUTPUT_DIR", outputDir.toString());

    log.info("Starting TypeScript cross-client tests: serverUrl={}, outputDir={}, filter={}",
        serverUrl, outputDir, testFilter);

    Process process = pb.start();

    // Capture output for logging
    StringBuilder output = new StringBuilder();
    try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line).append('\n');
        log.debug("[TS] {}", line);
      }
    }

    boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new RuntimeException("TypeScript test timed out after " + TIMEOUT_SECONDS + "s. Output:\n" + output);
    }

    int exitCode = process.exitValue();
    if (exitCode != 0) {
      log.warn("TypeScript tests exited with code {}. Output:\n{}", exitCode, output);
    } else {
      log.info("TypeScript cross-client tests passed");
    }
    return exitCode;
  }

  /**
   * Reads a result file written by the TypeScript test. Returns null if the file does not exist.
   */
  static String readResultFile(Path outputDir, String filename) throws IOException {
    Path file = outputDir.resolve(filename);
    if (!Files.exists(file)) {
      return null;
    }
    return Files.readString(file, StandardCharsets.UTF_8).trim();
  }

  private static Path findTypeScriptDir() {
    // Walk up from CWD looking for hofmann-typescript/
    Path dir = Path.of(System.getProperty("user.dir"));
    for (int i = 0; i < 5; i++) {
      Path candidate = dir.resolve("hofmann-typescript");
      if (Files.isDirectory(candidate) && Files.exists(candidate.resolve("package.json"))) {
        return candidate;
      }
      dir = dir.getParent();
      if (dir == null) break;
    }
    return null;
  }
}
