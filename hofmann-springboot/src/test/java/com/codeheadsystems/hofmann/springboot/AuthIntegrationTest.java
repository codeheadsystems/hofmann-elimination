package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.client.accessor.OpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.OpaqueManager;
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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] CREDENTIAL_ID = "jwt-test@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private OpaqueManager opaqueManager;
  private HttpClient httpClient;

  @BeforeEach
  void setUp() {
    httpClient = HttpClient.newHttpClient();
    OpaqueClientConfig config = OpaqueClientConfig.forTesting("hofmann-test");
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    OpaqueAccessor accessor = new OpaqueAccessor(httpClient, new ObjectMapper(), connections);
    opaqueManager = new OpaqueManager(config, accessor);
  }

  @Test
  void authenticateAndCallProtectedEndpoint_returns200() throws Exception {
    opaqueManager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);
    AuthFinishResponse authResp = opaqueManager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/api/whoami"))
        .header("Authorization", "Bearer " + authResp.token())
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).contains("credentialIdentifier");
  }

  @Test
  void callProtectedEndpoint_noToken_returns401() throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/api/whoami"))
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    assertThat(response.statusCode()).isEqualTo(401);
  }

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
