package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.OpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.OpaqueManager;
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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpaqueIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private OpaqueManager opaqueManager;

  @BeforeEach
  void setUp() {
    OpaqueClientConfig config = OpaqueClientConfig.forTesting("hofmann-test");
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    OpaqueAccessor accessor = new OpaqueAccessor(HttpClient.newHttpClient(),
        new ObjectMapper(), connections);
    opaqueManager = new OpaqueManager(config, accessor);
  }

  @Test
  void register_completesWithoutError() {
    byte[] credId = "register-only@example.com".getBytes(StandardCharsets.UTF_8);
    opaqueManager.register(SERVER_ID, credId, PASSWORD);
  }

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

    assertThat(resp1.sessionKeyBase64()).isNotEqualTo(resp2.sessionKeyBase64());
    assertThat(resp1.token()).isNotEqualTo(resp2.token());
  }

  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    byte[] credId = "wrong-pwd@example.com".getBytes(StandardCharsets.UTF_8);
    opaqueManager.register(SERVER_ID, credId, PASSWORD);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(() -> opaqueManager.authenticate(SERVER_ID, credId, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void deleteRegistration_completesWithoutError() {
    byte[] credId = "delete-me@example.com".getBytes(StandardCharsets.UTF_8);
    opaqueManager.register(SERVER_ID, credId, PASSWORD);
    opaqueManager.deleteRegistration(SERVER_ID, credId);
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
