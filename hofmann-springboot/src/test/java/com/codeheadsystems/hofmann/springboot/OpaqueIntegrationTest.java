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
   * Registration must leave a credential the server can actually authenticate against.
   *
   * <p>This previously had no assertions at all and passed on anything that did not throw,
   * including a server that accepted the registration and discarded it. Authenticating is the
   * only observation that distinguishes those two.
   */
  @Test
  void register_storesACredentialThatCanThenAuthenticate() {
    byte[] credId = "register-only@example.com".getBytes(StandardCharsets.UTF_8);

    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);

    assertThat(hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD).token())
        .isNotEmpty();
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
    // Unique credential id: the shared app/credential store persists across test methods and
    // normal registration no longer overwrites an existing record.
    byte[] credId = "auth-twice@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);

    AuthFinishResponse resp1 = hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse resp2 = hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD);

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
   * Deleting a registration must actually remove it.
   *
   * <p>The previous version called delete and asserted nothing, so it could not tell a real
   * deletion from a no-op that returned 204. What makes the deletion observable is that the
   * credential can no longer authenticate afterwards — the property a user deleting their account
   * is actually asking for.
   */
  @Test
  void deleteRegistration_withValidToken_preventsFurtherAuthentication() {
    byte[] credId = "delete-me@example.com".getBytes(StandardCharsets.UTF_8);
    hofmannOpaqueClientManager.register(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse authResp = hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD);

    hofmannOpaqueClientManager.deleteRegistration(SERVER_ID, credId, authResp.token());

    assertThatThrownBy(() -> hofmannOpaqueClientManager.authenticate(SERVER_ID, credId, PASSWORD))
        .as("a deleted credential must not authenticate")
        .isInstanceOf(SecurityException.class);
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
