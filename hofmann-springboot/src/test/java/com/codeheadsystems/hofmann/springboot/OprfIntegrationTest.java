package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOprfClientManager;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.rfc.oprf.manager.OprfClientManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * The type Oprf integration test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OprfIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

  @LocalServerPort
  private int port;

  private HofmannOprfClientManager hofmannOprfClientManager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    OprfClientConfig oprfClientConfig = new OprfClientConfig();
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf")));
    HofmannOprfAccessor accessor = new HofmannOprfAccessor(oprfClientConfig, HttpClient.newHttpClient(), new ObjectMapper(), connections);
    OprfClientManager oprfClientManager = new OprfClientManager(oprfClientConfig.suite());
    hofmannOprfClientManager = new HofmannOprfClientManager(accessor, oprfClientManager);
  }

  /**
   * Perform hash returns non empty hash.
   */
  @Test
  void performHash_returnsNonEmptyHash() {
    HofmannHashResult result = hofmannOprfClientManager.performHash("my-sensitive-input", SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("test-processor");
    assertThat(result.requestId()).isNotEmpty();
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  /**
   * Perform hash different inputs produce different hashes.
   */
  @Test
  void performHash_differentInputsProduceDifferentHashes() {
    HofmannHashResult result1 = hofmannOprfClientManager.performHash("input-one", SERVER_ID);
    HofmannHashResult result2 = hofmannOprfClientManager.performHash("input-two", SERVER_ID);

    assertThat(result1.hash()).isNotEqualTo(result2.hash());
  }

  /**
   * Perform hash same input produces same hash.
   */
  @Test
  void performHash_sameInputProducesSameHash() {
    HofmannHashResult result1 = hofmannOprfClientManager.performHash("stable-input", SERVER_ID);
    HofmannHashResult result2 = hofmannOprfClientManager.performHash("stable-input", SERVER_ID);

    assertThat(result1.hash()).isEqualTo(result2.hash());
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
