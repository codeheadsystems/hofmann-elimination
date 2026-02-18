package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.client.accessor.OprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.manager.OprfManager;
import com.codeheadsystems.hofmann.client.model.HashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OprfIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

  @LocalServerPort
  private int port;

  private OprfManager oprfManager;

  @BeforeEach
  void setUp() {
    OprfConfig oprfConfig = new OprfConfig();
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf")));
    OprfAccessor accessor = new OprfAccessor(oprfConfig, HttpClient.newHttpClient(),
        new ObjectMapper(), connections);
    oprfManager = new OprfManager(accessor, oprfConfig);
  }

  @Test
  void performHash_returnsNonEmptyHash() {
    HashResult result = oprfManager.performHash("my-sensitive-input", SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("test-processor");
    assertThat(result.requestId()).isNotEmpty();
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  @Test
  void performHash_differentInputsProduceDifferentHashes() {
    HashResult result1 = oprfManager.performHash("input-one", SERVER_ID);
    HashResult result2 = oprfManager.performHash("input-two", SERVER_ID);

    assertThat(result1.hash()).isNotEqualTo(result2.hash());
  }

  @Test
  void performHash_sameInputProducesSameHash() {
    HashResult result1 = oprfManager.performHash("stable-input", SERVER_ID);
    HashResult result2 = oprfManager.performHash("stable-input", SERVER_ID);

    assertThat(result1.hash()).isEqualTo(result2.hash());
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
