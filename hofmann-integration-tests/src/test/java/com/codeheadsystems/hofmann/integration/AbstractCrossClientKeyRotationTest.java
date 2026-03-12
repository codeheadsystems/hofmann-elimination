package com.codeheadsystems.hofmann.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Cross-client key rotation tests: validates that a credential registered under old keys
 * can be authenticated (and auto-migrated) by the other client after key rotation.
 */
abstract class AbstractCrossClientKeyRotationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] PASSWORD = "rotation-cross-client-pwd".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  @Autowired
  private MutableKeyDetailSupplier keyDetailSupplier;

  @Autowired
  private OpaqueConfig opaqueConfig;

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
    cleanExchangeFiles();
  }

  @AfterEach
  void tearDown() {
    keyDetailSupplier.reset();
  }

  @Test
  void javaRegisters_keysRotate_typeScriptAuthenticatesAndAutoMigrates() throws Exception {
    assumeThat(TypeScriptRunner.isTypeScriptAvailable())
        .as("TypeScript module must be built")
        .isTrue();
    assumeThat(TypeScriptRunner.isTypeScriptSuiteSupported(cipherSuiteName()))
        .as("TypeScript client must support cipher suite " + cipherSuiteName())
        .isTrue();

    // Java registers under version 0
    String credId = "java-rotation-" + cipherSuiteName() + "@cross-client.test";
    manager.register(SERVER_ID, credId.getBytes(StandardCharsets.UTF_8), PASSWORD);

    // Rotate to version 1
    keyDetailSupplier.rotateKeys(Server.generate(opaqueConfig));

    // Write credential info for TS to authenticate (which triggers auto-migration)
    Files.writeString(outputDir.resolve("opaque-rotation-cred.txt"), credId);
    Files.writeString(outputDir.resolve("opaque-rotation-pwd.txt"), "rotation-cross-client-pwd");

    int exitCode = TypeScriptRunner.runCrossClientTest(
        baseUrl(), outputDir, "authenticates and auto-migrates after key rotation");
    assertThat(exitCode).as("TypeScript key rotation auth test exit code").isZero();

    String tsResult = TypeScriptRunner.readResultFile(outputDir, "opaque-ts-rotation-result.txt");
    assertThat(tsResult)
        .as("TypeScript rotation auth result")
        .isNotNull()
        .isEqualTo("success");

    // Verify migration worked: Java authenticates at current version (no rotation flag)
    AuthFinishResponse resp = manager.authenticate(
        SERVER_ID, credId.getBytes(StandardCharsets.UTF_8), PASSWORD);
    assertThat(resp.token()).isNotEmpty();
    assertThat(resp.keyRotationRequired()).isNull();
  }

  @Test
  void typeScriptRegisters_keysRotate_javaAuthenticatesAndAutoMigrates() throws Exception {
    assumeThat(TypeScriptRunner.isTypeScriptAvailable())
        .as("TypeScript module must be built")
        .isTrue();
    assumeThat(TypeScriptRunner.isTypeScriptSuiteSupported(cipherSuiteName()))
        .as("TypeScript client must support cipher suite " + cipherSuiteName())
        .isTrue();

    String credId = "ts-rotation-" + cipherSuiteName() + "@cross-client.test";
    String password = "rotation-cross-client-pwd";

    // Write credential info for TS to register
    Files.writeString(outputDir.resolve("opaque-ts-register-cred.txt"), credId);
    Files.writeString(outputDir.resolve("opaque-ts-register-pwd.txt"), password);

    // TS registers under version 0
    int exitCode = TypeScriptRunner.runCrossClientTest(
        baseUrl(), outputDir, "registers a credential for Java");
    assertThat(exitCode).as("TypeScript registration test exit code").isZero();

    String tsRegResult = TypeScriptRunner.readResultFile(outputDir, "opaque-ts-reg-result.txt");
    assertThat(tsRegResult).isNotNull().isEqualTo("success");

    // Rotate to version 1
    keyDetailSupplier.rotateKeys(Server.generate(opaqueConfig));

    // Java authenticates — auto-migrates via keyRotationRequired
    AuthFinishResponse resp1 = manager.authenticate(
        SERVER_ID, credId.getBytes(StandardCharsets.UTF_8),
        password.getBytes(StandardCharsets.UTF_8));
    assertThat(resp1.token()).isNotEmpty();
    assertThat(resp1.keyRotationRequired()).isTrue();

    // Second auth — no rotation needed
    AuthFinishResponse resp2 = manager.authenticate(
        SERVER_ID, credId.getBytes(StandardCharsets.UTF_8),
        password.getBytes(StandardCharsets.UTF_8));
    assertThat(resp2.token()).isNotEmpty();
    assertThat(resp2.keyRotationRequired()).isNull();
  }

  private void cleanExchangeFiles() throws java.io.IOException {
    String[] files = {
        "opaque-rotation-cred.txt", "opaque-rotation-pwd.txt",
        "opaque-ts-rotation-result.txt",
        "opaque-ts-register-cred.txt", "opaque-ts-register-pwd.txt",
        "opaque-ts-reg-result.txt"
    };
    for (String f : files) {
      Files.deleteIfExists(outputDir.resolve(f));
    }
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
