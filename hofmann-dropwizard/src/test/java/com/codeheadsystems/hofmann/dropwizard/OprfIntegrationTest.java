package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOprfClientManager;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
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
 * the {@link HofmannOprfClientManager} / {@link HofmannOprfAccessor} client stack from {@code hofmann-client}.
 * <p>
 * Starts a real embedded Jetty server via Dropwizard's test support and drives the full
 * client-side OPRF flow over HTTP.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class OprfIntegrationTest {

  /**
   * The App.
   */
  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config.yml"));

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

  private HofmannOprfClientManager hofmannOprfClientManager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    OprfClientConfig oprfClientConfig = new OprfClientConfig();
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf")));
    HofmannOprfAccessor accessor = new HofmannOprfAccessor(oprfClientConfig, HttpClient.newHttpClient(),
        new ObjectMapper(), connections);
    hofmannOprfClientManager = new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, oprfClientConfig));
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
    // Because the OPRF master key is fixed for a server instance within a run, and the
    // OPRF finalization is deterministic given the same blinding-unblinding round-trip,
    // the same input must yield the same final hash value.
    HofmannHashResult result1 = hofmannOprfClientManager.performHash("stable-input", SERVER_ID);
    HofmannHashResult result2 = hofmannOprfClientManager.performHash("stable-input", SERVER_ID);

    assertThat(result1.hash()).isEqualTo(result2.hash());
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }
}
