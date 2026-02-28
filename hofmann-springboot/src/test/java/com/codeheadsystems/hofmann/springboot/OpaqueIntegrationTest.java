package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * The type Opaque integration test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpaqueIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private HofmannOpaqueClientManager hofmannOpaqueClientManager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    OpaqueClientConfig config = OpaqueClientConfig.forTesting("hofmann-test");
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(HttpClient.newHttpClient(),
        new ObjectMapper(), connections);
    hofmannOpaqueClientManager = new HofmannOpaqueClientManager(accessor, Map.of(SERVER_ID, config));
  }

  /**
   * Register completes without error.
   */
  @Test
  void register_completesWithoutError() {
    byte[] credId = "register-only@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);
  }

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

    assertThat(resp1.sessionKeyBase64()).isNotEqualTo(resp2.sessionKeyBase64());
    assertThat(resp1.token()).isNotEqualTo(resp2.token());
  }

  /**
   * Authenticate wrong password throws security exception.
   */
  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    byte[] credId = "wrong-pwd@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(() -> hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * Delete registration with valid token completes without error.
   */
  @Test
  void deleteRegistration_withValidToken_completesWithoutError() {
    byte[] credId = "delete-me@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse authResp = hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD);
    hofmannOpaqueClientManager.deleteRegistration(SERVER_ID, credId, authResp.token());
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
    return String.format("http://localhost:%d", port);
  }
}
