package com.codeheadsystems.hofmann.integration;

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
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Base OPAQUE integration test class. Subclasses configure cipher suites via
 * {@code @SpringBootTest(properties = ...)}.
 */
abstract class AbstractOpaqueIntegrationTest {

  protected static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  protected static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private HofmannOpaqueClientManager manager;
  private HttpClient httpClient;

  /**
   * Returns the cipher suite name for this test class (e.g. "P256_SHA256").
   */
  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() {
    httpClient = HttpClient.newHttpClient();
    OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
        cipherSuiteName(), "integration-test", 1024, 1, 1);
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(
        httpClient, new ObjectMapper(), connections);
    manager = new HofmannOpaqueClientManager(accessor, Map.of(SERVER_ID, config));
  }

  @Test
  void register_completesWithoutError() {
    byte[] credId = uniqueCredId("register-only");
    manager.register(SERVER_ID, credId, PASSWORD);
  }

  @Test
  void registerThenAuthenticate_derivesMatchingSessionKey() {
    byte[] credId = uniqueCredId("auth");
    manager.register(SERVER_ID, credId, PASSWORD);

    AuthFinishResponse response = manager.authenticate(SERVER_ID, credId, PASSWORD);

    assertThat(response.sessionKeyBase64()).isNotEmpty();
    assertThat(response.token()).isNotEmpty();
  }

  @Test
  void authenticateTwice_producesDifferentSessionKeys() {
    byte[] credId = uniqueCredId("auth-twice");
    manager.register(SERVER_ID, credId, PASSWORD);

    AuthFinishResponse resp1 = manager.authenticate(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse resp2 = manager.authenticate(SERVER_ID, credId, PASSWORD);

    assertThat(resp1.sessionKeyBase64()).isNotEqualTo(resp2.sessionKeyBase64());
    assertThat(resp1.token()).isNotEqualTo(resp2.token());
  }

  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    byte[] credId = uniqueCredId("wrong-pwd");
    manager.register(SERVER_ID, credId, PASSWORD);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(() -> manager.authenticate(SERVER_ID, credId, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void deleteRegistration_withValidToken_completesWithoutError() {
    byte[] credId = uniqueCredId("delete-ok");
    manager.register(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse authResp = manager.authenticate(SERVER_ID, credId, PASSWORD);
    manager.deleteRegistration(SERVER_ID, credId, authResp.token());
  }

  @Test
  void deleteRegistration_withoutToken_throwsSecurityException() {
    byte[] credId = uniqueCredId("delete-noauth");
    manager.register(SERVER_ID, credId, PASSWORD);

    assertThatThrownBy(() -> manager.deleteRegistration(SERVER_ID, credId, null))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void authenticateAndCallProtectedEndpoint_returns200() throws Exception {
    byte[] credId = uniqueCredId("whoami");
    manager.register(SERVER_ID, credId, PASSWORD);
    AuthFinishResponse authResp = manager.authenticate(SERVER_ID, credId, PASSWORD);

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/api/whoami"))
        .header("Authorization", "Bearer " + authResp.token())
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).contains("credentialIdentifier");
  }

  // ── Recovery integration tests ──────────────────────────────────────────────

  @Test
  void recoveryStart_returns202() throws Exception {
    byte[] credId = uniqueCredId("recovery-start");
    manager.register(SERVER_ID, credId, PASSWORD);

    HttpResponse<String> response = postJson(
        "/opaque/recovery/start",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\"}",
        null);
    assertThat(response.statusCode()).isEqualTo(202);
  }

  @Test
  void recoveryVerify_returnsToken() throws Exception {
    byte[] credId = uniqueCredId("recovery-verify");
    manager.register(SERVER_ID, credId, PASSWORD);

    // Send challenge
    postJson("/opaque/recovery/start",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\"}", null);

    // Verify with the fixed test code
    HttpResponse<String> verifyResp = postJson(
        "/opaque/recovery/verify",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\",\"challengeResponse\":\"123456\"}",
        null);
    assertThat(verifyResp.statusCode()).isEqualTo(200);
    assertThat(verifyResp.body()).contains("recoveryToken");
  }

  @Test
  void recoveryVerify_wrongCode_returns401() throws Exception {
    byte[] credId = uniqueCredId("recovery-wrong-code");
    manager.register(SERVER_ID, credId, PASSWORD);

    postJson("/opaque/recovery/start",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\"}", null);

    HttpResponse<String> verifyResp = postJson(
        "/opaque/recovery/verify",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\",\"challengeResponse\":\"wrong\"}",
        null);
    assertThat(verifyResp.statusCode()).isEqualTo(401);
  }

  @Test
  void fullRecoveryFlow_reRegistersAndAuthenticatesWithNewPassword() throws Exception {
    byte[] credId = uniqueCredId("recovery-full");
    byte[] newPassword = "new-password-after-recovery".getBytes(StandardCharsets.UTF_8);

    // Register with original password
    manager.register(SERVER_ID, credId, PASSWORD);
    // Verify original password works
    AuthFinishResponse origAuth = manager.authenticate(SERVER_ID, credId, PASSWORD);
    assertThat(origAuth.token()).isNotEmpty();

    // Recovery flow: start → verify → get token
    postJson("/opaque/recovery/start",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\"}", null);
    HttpResponse<String> verifyResp = postJson(
        "/opaque/recovery/verify",
        "{\"credentialIdentifier\":\"" + b64(credId) + "\",\"challengeResponse\":\"123456\"}",
        null);
    ObjectMapper mapper = new ObjectMapper();
    String recoveryToken = mapper.readTree(verifyResp.body()).get("recoveryToken").asText();

    // Re-register with new password using recovery token
    manager.register(SERVER_ID, credId, newPassword, recoveryToken);

    // Authenticate with new password
    AuthFinishResponse newAuth = manager.authenticate(SERVER_ID, credId, newPassword);
    assertThat(newAuth.sessionKeyBase64()).isNotEmpty();
    assertThat(newAuth.token()).isNotEmpty();

    // Old password should fail
    assertThatThrownBy(() -> manager.authenticate(SERVER_ID, credId, PASSWORD))
        .isInstanceOf(SecurityException.class);
  }

  private HttpResponse<String> postJson(String path, String body, String bearerToken) throws Exception {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + path))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body));
    if (bearerToken != null) {
      builder.header("Authorization", "Bearer " + bearerToken);
    }
    return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
  }

  private static String b64(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }

  protected String baseUrl() {
    return String.format("http://localhost:%d", port);
  }

  protected HofmannOpaqueClientManager getManager() {
    return manager;
  }

  /**
   * Generates a unique credential ID to avoid collisions between test methods
   * (in-memory store is shared within the same application context).
   */
  private byte[] uniqueCredId(String suffix) {
    return (cipherSuiteName() + "-" + suffix + "@example.com").getBytes(StandardCharsets.UTF_8);
  }
}
