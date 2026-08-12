package com.codeheadsystems.hofmann.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOprfClientManager;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.server.oprf.VerifiableKeyConfig;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Cross-client VOPRF and POPRF: the TypeScript client verifies a DLEQ proof produced by the Java
 * server, and both clients must arrive at the same outputs.
 *
 * <p>This is the test that would notice the ports disagreeing on the proof transcript. A prover
 * and verifier written from the same misreading interoperate perfectly with each other, so
 * per-language round trips cannot catch it and only the RFC vectors or an actual cross-language
 * exchange can. The vectors are checked in each language already; this checks the exchange.
 *
 * <p><strong>The pinned public key is derived here from the configured master key</strong> and
 * handed to the TypeScript side through a file — not fetched from the server. A proof graded
 * against a key the same server supplied would verify no matter which key the server actually
 * used, which would make this test unable to fail.
 */
abstract class AbstractCrossClientVerifiableOprfTest {

  /** Must match {@code application.yml}. */
  private static final String VOPRF_MASTER_KEY_HEX =
      "4a1f9c3e7b25d8064f13a9e5c72b8d40e916f3a7c5b2d894e0163a7fc9d5b2e8";
  private static final String POPRF_MASTER_KEY_HEX =
      "7d2e5b91c4f38a06e7b1d945c83f2b60a94e7d31f85c206b3e7a9d148f5c2b30";

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

  // Must match the constants in hofmann-typescript/test/cross-client.test.ts.
  private static final List<byte[]> VOPRF_INPUTS = List.of(
      "cross-client-voprf-alpha".getBytes(StandardCharsets.UTF_8),
      "cross-client-voprf-beta".getBytes(StandardCharsets.UTF_8));
  private static final List<byte[]> POPRF_INPUTS = List.of(
      "cross-client-poprf-alpha".getBytes(StandardCharsets.UTF_8),
      "cross-client-poprf-beta".getBytes(StandardCharsets.UTF_8));
  private static final byte[] POPRF_INFO = "cross-client-tenant".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private HofmannOprfAccessor accessor;
  private HofmannOprfClientManager manager;
  private Path outputDir;

  /**
   * Returns the cipher suite name for this test class (e.g. "P256_SHA256").
   *
   * @return the suite name
   */
  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() throws Exception {
    accessor = new HofmannOprfAccessor(new OprfClientConfig(), HttpClient.newHttpClient(),
        new ObjectMapper(),
        Map.of(SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf"))));
    OprfClientConfig config = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.valueOf(cipherSuiteName())).build())
        .withVoprfServerPublicKey(publicKeyHex(OprfMode.VOPRF))
        .withPoprfServerPublicKey(publicKeyHex(OprfMode.POPRF));
    manager = new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, config));
    outputDir = Path.of(
        System.getProperty("java.io.tmpdir"), "hofmann-integration", cipherSuiteName());
    Files.createDirectories(outputDir);
  }

  /**
   * Derives the public key independently of the server, from the same master key the deployment
   * configures. The processor identifier is read back from the advertised config because the two
   * framework adapters spell it differently and this test is about the keys.
   */
  private String publicKeyHex(final OprfMode mode) {
    String processorId = accessor.getOprfConfig(SERVER_ID).modes().stream()
        .filter(m -> m.mode().equals(mode.name()))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException(mode + " is not enabled on the test server"))
        .processIdentifier();
    OprfCipherSuite suite =
        VerifiableKeyConfig.suiteFor(cipherSuiteName(), mode, new SecureRandom());
    String masterKey = mode == OprfMode.VOPRF ? VOPRF_MASTER_KEY_HEX : POPRF_MASTER_KEY_HEX;
    return HexFormat.of().formatHex(
        VerifiableKeyConfig.detailFrom(suite, masterKey, processorId, "test").publicKey());
  }

  private void assumeTypeScriptAvailable() {
    assumeThat(TypeScriptRunner.isTypeScriptAvailable())
        .as("TypeScript module must be built (npm install && npm run build in hofmann-typescript/)")
        .isTrue();
    assumeThat(TypeScriptRunner.isTypeScriptSuiteSupported(cipherSuiteName()))
        .as("TypeScript client must support cipher suite " + cipherSuiteName())
        .isTrue();
  }

  private static String joinHex(final List<HofmannHashResult> results) {
    return results.stream()
        .map(r -> HexFormat.of().formatHex(r.hash()))
        .collect(Collectors.joining("\n"));
  }

  @Test
  void javaAndTypeScriptAgreeOnAVerifiedVoprfBatch() throws Exception {
    assumeTypeScriptAvailable();

    String javaHex = joinHex(manager.performVerifiableHash(VOPRF_INPUTS, SERVER_ID));
    Files.writeString(outputDir.resolve("voprf-java.txt"), javaHex);
    Files.writeString(outputDir.resolve("voprf-pks.txt"), publicKeyHex(OprfMode.VOPRF));

    int exitCode = TypeScriptRunner.runCrossClientTest(baseUrl(), outputDir, "cross-client VOPRF");
    assertThat(exitCode).as("TypeScript cross-client VOPRF test exit code").isZero();

    String tsHex = TypeScriptRunner.readResultFile(outputDir, "voprf-ts.txt");
    assertThat(tsHex)
        .as("TypeScript VOPRF outputs for suite %s", cipherSuiteName())
        .isNotNull()
        .isEqualTo(javaHex);
  }

  @Test
  void javaAndTypeScriptAgreeOnAVerifiedPoprfBatch() throws Exception {
    assumeTypeScriptAvailable();

    String javaHex =
        joinHex(manager.performPartiallyObliviousHash(POPRF_INPUTS, POPRF_INFO, SERVER_ID));
    Files.writeString(outputDir.resolve("poprf-java.txt"), javaHex);
    Files.writeString(outputDir.resolve("poprf-pks.txt"), publicKeyHex(OprfMode.POPRF));
    Files.writeString(
        outputDir.resolve("poprf-info.txt"), HexFormat.of().formatHex(POPRF_INFO));

    int exitCode = TypeScriptRunner.runCrossClientTest(baseUrl(), outputDir, "cross-client POPRF");
    assertThat(exitCode).as("TypeScript cross-client POPRF test exit code").isZero();

    String tsHex = TypeScriptRunner.readResultFile(outputDir, "poprf-ts.txt");
    assertThat(tsHex)
        .as("TypeScript POPRF outputs for suite %s", cipherSuiteName())
        .isNotNull()
        .isEqualTo(javaHex);
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
