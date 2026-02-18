package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.OpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.OpaqueManager;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Integration tests for the OPAQUE-3DH endpoints exercised through the
 * {@link OpaqueManager} / {@link OpaqueAccessor} client stack from {@code hofmann-client}.
 * <p>
 * Starts a real embedded Jetty server via Dropwizard's test support and drives the full
 * OPAQUE registration and authentication flows over HTTP.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class OpaqueIntegrationTest {

  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config.yml"));

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  private OpaqueManager opaqueManager;

  @BeforeEach
  void setUp() {
    // Context must match test-config.yml so the preamble hash aligns between client and server
    OpaqueClientConfig config = OpaqueClientConfig.forTesting("hofmann-test");
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    OpaqueAccessor accessor = new OpaqueAccessor(HttpClient.newHttpClient(),
        new ObjectMapper(), connections);
    opaqueManager = new OpaqueManager(config, accessor);
  }

  // ── Registration ─────────────────────────────────────────────────────────

  @Test
  void register_completesWithoutError() {
    byte[] credId = "register-only@example.com".getBytes(StandardCharsets.UTF_8);
    opaqueManager.register(SERVER_ID, credId, PASSWORD);
    // No exception = success; the server stored the record
  }

  // ── Full round trip ───────────────────────────────────────────────────────

  @Test
  void registerThenAuthenticate_derivesMatchingSessionKey() {
    opaqueManager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    AuthFinishResponse response = opaqueManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    assertThat(response.sessionKeyBase64()).isNotEmpty();
    assertThat(response.token()).isNotEmpty();
  }

  @Test
  void authenticateTwice_producesDifferentSessionKeys() {
    opaqueManager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    AuthFinishResponse resp1 = opaqueManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);
    AuthFinishResponse resp2 = opaqueManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    // Each 3DH handshake uses fresh ephemeral keys and nonces, so session keys must differ
    assertThat(resp1.sessionKeyBase64()).isNotEqualTo(resp2.sessionKeyBase64());
    // Tokens must also be different
    assertThat(resp1.token()).isNotEqualTo(resp2.token());
  }

  // ── Wrong password ────────────────────────────────────────────────────────

  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    byte[] credId = "wrong-pwd@example.com".getBytes(StandardCharsets.UTF_8);
    opaqueManager.register(SERVER_ID, credId, PASSWORD);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    // With the wrong password the client fails to verify the server MAC in KE2,
    // so generateKE3 throws SecurityException before the /auth/finish call is made.
    assertThatThrownBy(() -> opaqueManager.authenticate(SERVER_ID, credId, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  // ── Delete ────────────────────────────────────────────────────────────────

  @Test
  void deleteRegistration_completesWithoutError() {
    byte[] credId = "delete-me@example.com".getBytes(StandardCharsets.UTF_8);
    opaqueManager.register(SERVER_ID, credId, PASSWORD);
    opaqueManager.deleteRegistration(SERVER_ID, credId);
    // No exception = server accepted the delete
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }
}
