package com.codeheadsystems.hofmann.integration;

import static org.assertj.core.api.Assertions.assertThat;

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
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Base OPRF integration test class. Subclasses configure cipher suites via
 * {@code @SpringBootTest(properties = ...)}.
 */
abstract class AbstractOprfIntegrationTest {

  protected static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

  @LocalServerPort
  private int port;

  private HofmannOprfClientManager manager;

  /**
   * Returns the cipher suite name for this test class (e.g. "P256_SHA256").
   */
  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() {
    OprfClientConfig config = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.valueOf(cipherSuiteName())).build());
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf")));
    HofmannOprfAccessor accessor = new HofmannOprfAccessor(
        config, HttpClient.newHttpClient(), new ObjectMapper(), connections);
    manager = new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, config));
  }

  @Test
  void performHash_returnsNonEmptyHash() {
    HofmannHashResult result = manager.performHash("integration-test-input", SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("integration-processor");
    assertThat(result.requestId()).isNotEmpty();
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  @Test
  void performHash_differentInputsProduceDifferentHashes() {
    HofmannHashResult result1 = manager.performHash("input-alpha", SERVER_ID);
    HofmannHashResult result2 = manager.performHash("input-beta", SERVER_ID);

    assertThat(result1.hash()).isNotEqualTo(result2.hash());
  }

  @Test
  void performHash_sameInputProducesSameHash() {
    HofmannHashResult result1 = manager.performHash("deterministic-input", SERVER_ID);
    HofmannHashResult result2 = manager.performHash("deterministic-input", SERVER_ID);

    assertThat(result1.hash()).isEqualTo(result2.hash());
  }

  protected String baseUrl() {
    return String.format("http://localhost:%d", port);
  }

  protected HofmannOprfClientManager getManager() {
    return manager;
  }
}
