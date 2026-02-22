package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
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
 * {@link HofmannOpaqueClientManager} / {@link HofmannOpaqueAccessor} client stack from {@code hofmann-client}.
 * <p>
 * Starts a real embedded Jetty server via Dropwizard's test support and drives the full
 * OPAQUE registration and authentication flows over HTTP.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class OpaqueIntegrationTest {

  /**
   * The App.
   */
  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config.yml"));

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  private HofmannOpaqueClientManager hofmannOpaqueClientManager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    // Context must match test-config.yml so the preamble hash aligns between client and server
    OpaqueClientConfig config = OpaqueClientConfig.forTesting("hofmann-test");
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(HttpClient.newHttpClient(),
        new ObjectMapper(), connections);
    hofmannOpaqueClientManager = new HofmannOpaqueClientManager(config, accessor);
  }

  // ── Registration ─────────────────────────────────────────────────────────

  /**
   * Register completes without error.
   */
  @Test
  void register_completesWithoutError() {
    byte[] credId = "register-only@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);
    // No exception = success; the server stored the record
  }

  // ── Full round trip ───────────────────────────────────────────────────────

  /**
   * Register then authenticate derives matching session key.
   */
  @Test
  void registerThenAuthenticate_derivesMatchingSessionKey() {
    hofmannOpaqueClientManager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    AuthFinishResponse response = hofmannOpaqueClientManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    assertThat(response.sessionKeyBase64()).isNotEmpty();
    assertThat(response.token()).isNotEmpty();
  }

  /**
   * Authenticate twice produces different session keys.
   */
  @Test
  void authenticateTwice_producesDifferentSessionKeys() {
    hofmannOpaqueClientManager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    AuthFinishResponse resp1 = hofmannOpaqueClientManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);
    AuthFinishResponse resp2 = hofmannOpaqueClientManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    // Each 3DH handshake uses fresh ephemeral keys and nonces, so session keys must differ
    assertThat(resp1.sessionKeyBase64()).isNotEqualTo(resp2.sessionKeyBase64());
    // Tokens must also be different
    assertThat(resp1.token()).isNotEqualTo(resp2.token());
  }

  // ── Wrong password ────────────────────────────────────────────────────────

  /**
   * Authenticate wrong password throws security exception.
   */
  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    byte[] credId = "wrong-pwd@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    // With the wrong password the client fails to verify the server MAC in KE2,
    // so generateKE3 throws SecurityException before the /auth/finish call is made.
    assertThatThrownBy(() -> hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  // ── Delete ────────────────────────────────────────────────────────────────

  /**
   * Delete registration with valid token completes without error.
   */
  @Test
  void deleteRegistration_withValidToken_completesWithoutError() {
    byte[] credId = "delete-me@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse authResp = hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD);
    hofmannOpaqueClientManager.deleteRegistration(SERVER_ID, credId, authResp.token());
    // No exception = server accepted the delete
  }

  /**
   * Delete registration without token throws security exception.
   */
  @Test
  void deleteRegistration_withoutToken_throwsSecurityException() {
    byte[] credId = "delete-noauth@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);
    assertThatThrownBy(() -> hofmannOpaqueClientManager.deleteRegistration(SERVER_ID, credId, null))
        .isInstanceOf(SecurityException.class);
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }
}
