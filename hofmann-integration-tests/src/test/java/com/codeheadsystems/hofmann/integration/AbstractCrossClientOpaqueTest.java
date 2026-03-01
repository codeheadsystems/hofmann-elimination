package com.codeheadsystems.hofmann.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Base cross-client OPAQUE test: validates that a user registered with one client
 * (Java or TypeScript) can authenticate with the other client.
 */
abstract class AbstractCrossClientOpaqueTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] PASSWORD = "cross-client-password".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private HofmannOpaqueClientManager manager;
  private Path outputDir;

  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() throws Exception {
    OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
        cipherSuiteName(), "integration-test", 1024, 1, 1);
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(
        HttpClient.newHttpClient(), new ObjectMapper(), connections);
    manager = new HofmannOpaqueClientManager(accessor, Map.of(SERVER_ID, config));
    outputDir = Path.of(System.getProperty("java.io.tmpdir"), "hofmann-integration", cipherSuiteName());
    Files.createDirectories(outputDir);
    // Clean all exchange files to avoid cross-contamination between tests
    cleanExchangeFiles();
  }

  @Test
  void javaRegisters_typeScriptAuthenticates() throws Exception {
    assumeThat(TypeScriptRunner.isTypeScriptAvailable())
        .as("TypeScript module must be built (npm install && npm run build in hofmann-typescript/)")
        .isTrue();

    // Java client registers the user
    String credId = "java-reg-" + cipherSuiteName() + "@cross-client.test";
    manager.register(SERVER_ID, credId.getBytes(StandardCharsets.UTF_8), PASSWORD);

    // Write credential info for TypeScript to read
    Files.writeString(outputDir.resolve("opaque-java-registered-cred.txt"), credId);
    Files.writeString(outputDir.resolve("opaque-java-registered-pwd.txt"), "cross-client-password");

    // Run only the "authenticates with a credential registered by Java" TS test
    int exitCode = TypeScriptRunner.runCrossClientTest(
        baseUrl(), outputDir, "authenticates with a credential registered by Java");
    assertThat(exitCode).as("TypeScript cross-client OPAQUE auth test exit code").isZero();

    // Verify TypeScript successfully authenticated
    String tsAuthResult = TypeScriptRunner.readResultFile(outputDir, "opaque-ts-auth-result.txt");
    assertThat(tsAuthResult)
        .as("TypeScript auth result for Java-registered credential")
        .isNotNull()
        .isEqualTo("success");
  }

  @Test
  void typeScriptRegisters_javaAuthenticates() throws Exception {
    assumeThat(TypeScriptRunner.isTypeScriptAvailable())
        .as("TypeScript module must be built (npm install && npm run build in hofmann-typescript/)")
        .isTrue();

    String credId = "ts-reg-" + cipherSuiteName() + "@cross-client.test";
    String password = "cross-client-password";

    // Write credential info for TypeScript to register
    Files.writeString(outputDir.resolve("opaque-ts-register-cred.txt"), credId);
    Files.writeString(outputDir.resolve("opaque-ts-register-pwd.txt"), password);

    // Run only the "registers a credential for Java" TS test
    int exitCode = TypeScriptRunner.runCrossClientTest(
        baseUrl(), outputDir, "registers a credential for Java");
    assertThat(exitCode).as("TypeScript cross-client OPAQUE registration test exit code").isZero();

    // Verify TypeScript registered successfully
    String tsRegResult = TypeScriptRunner.readResultFile(outputDir, "opaque-ts-reg-result.txt");
    assertThat(tsRegResult)
        .as("TypeScript registration result")
        .isNotNull()
        .isEqualTo("success");

    // Java client authenticates with the credential registered by TypeScript
    AuthFinishResponse response = manager.authenticate(
        SERVER_ID, credId.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));

    assertThat(response.sessionKeyBase64()).isNotEmpty();
    assertThat(response.token()).isNotEmpty();
  }

  private void cleanExchangeFiles() throws IOException {
    String[] files = {
        "opaque-java-registered-cred.txt", "opaque-java-registered-pwd.txt",
        "opaque-ts-register-cred.txt", "opaque-ts-register-pwd.txt",
        "opaque-ts-auth-result.txt", "opaque-ts-reg-result.txt"
    };
    for (String f : files) {
      Files.deleteIfExists(outputDir.resolve(f));
    }
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
