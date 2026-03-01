package com.codeheadsystems.hofmann.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOprfClientManager;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Base cross-client OPRF test: Java client hashes an input, TypeScript client hashes the same
 * input, and the test verifies both produce identical results.
 */
abstract class AbstractCrossClientOprfTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final String CROSS_CLIENT_INPUT = "cross-client-oprf-test-input";

  @LocalServerPort
  private int port;

  private HofmannOprfClientManager manager;
  private Path outputDir;

  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() throws Exception {
    OprfClientConfig config = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.valueOf(cipherSuiteName())).build());
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf")));
    HofmannOprfAccessor accessor = new HofmannOprfAccessor(
        config, HttpClient.newHttpClient(), new ObjectMapper(), connections);
    manager = new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, config));
    outputDir = Path.of(System.getProperty("java.io.tmpdir"), "hofmann-integration", cipherSuiteName());
    Files.createDirectories(outputDir);
  }

  @Test
  void javaAndTypeScriptProduceSameOprfHash() throws Exception {
    assumeThat(TypeScriptRunner.isTypeScriptAvailable())
        .as("TypeScript module must be built (npm install && npm run build in hofmann-typescript/)")
        .isTrue();

    // Java client hashes the input
    HofmannHashResult javaResult = manager.performHash(CROSS_CLIENT_INPUT, SERVER_ID);
    String javaHashHex = HexFormat.of().formatHex(javaResult.hash());

    // Write Java result for reference
    Files.writeString(outputDir.resolve("oprf-java.txt"), javaHashHex);

    // Run TypeScript test
    int exitCode = TypeScriptRunner.runCrossClientTest(baseUrl(), outputDir, "cross-client OPRF");
    assertThat(exitCode).as("TypeScript cross-client OPRF test exit code").isZero();

    // Read TypeScript result and compare
    String tsHashHex = TypeScriptRunner.readResultFile(outputDir, "oprf-ts.txt");
    assertThat(tsHashHex)
        .as("TypeScript OPRF hash for input '%s' with suite %s", CROSS_CLIENT_INPUT, cipherSuiteName())
        .isNotNull()
        .isEqualTo(javaHashHex);
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
