package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.client.accessor.OprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.manager.OprfManager;
import com.codeheadsystems.hofmann.client.model.HashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Integration tests for the standalone OPRF endpoint ({@code POST /oprf}) exercised through
 * the {@link OprfManager} / {@link OprfAccessor} client stack from {@code hofmann-client}.
 * <p>
 * Starts a real embedded Jetty server via Dropwizard's test support and drives the full
 * client-side OPRF flow over HTTP.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class OprfIntegrationTest {

  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config.yml"));

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

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
    // Because the OPRF master key is fixed for a server instance within a run, and the
    // OPRF finalization is deterministic given the same blinding-unblinding round-trip,
    // the same input must yield the same final hash value.
    HashResult result1 = oprfManager.performHash("stable-input", SERVER_ID);
    HashResult result2 = oprfManager.performHash("stable-input", SERVER_ID);

    assertThat(result1.hash()).isEqualTo(result2.hash());
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }
}
