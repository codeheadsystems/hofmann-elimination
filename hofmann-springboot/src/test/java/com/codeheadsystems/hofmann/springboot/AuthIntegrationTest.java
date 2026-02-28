package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;

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
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * The type Auth integration test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] CREDENTIAL_ID = "jwt-test@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private HofmannOpaqueClientManager hofmannOpaqueClientManager;
  private HttpClient httpClient;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    httpClient = HttpClient.newHttpClient();
    OpaqueClientConfig config = OpaqueClientConfig.forTesting("hofmann-test");
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(httpClient, new ObjectMapper(), connections);
    hofmannOpaqueClientManager = new HofmannOpaqueClientManager(accessor, Map.of(SERVER_ID, config));
  }

  /**
   * Authenticate and call protected endpoint returns 200.
   *
   * @throws Exception the exception
   */
  @Test
  void authenticateAndCallProtectedEndpoint_returns200() throws Exception {
    hofmannOpaqueClientManager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);
    AuthFinishResponse authResp = hofmannOpaqueClientManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/api/whoami"))
        .header("Authorization", "Bearer " + authResp.token())
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).contains("credentialIdentifier");
  }

  /**
   * Call protected endpoint no token returns 401.
   *
   * @throws Exception the exception
   */
  @Test
  void callProtectedEndpoint_noToken_returns401() throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/api/whoami"))
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(401);
  }

  /**
   * Call protected endpoint bogus token returns 401.
   *
   * @throws Exception the exception
   */
  @Test
  void callProtectedEndpoint_bogusToken_returns401() throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/api/whoami"))
        .header("Authorization", "Bearer not-a-real-token")
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(401);
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }
}
