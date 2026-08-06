package com.codeheadsystems.hofmann.springboot;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Spring forwards an error to {@code /error}, and the security chain sees that forward as a
 * separate, unauthenticated request. Without an explicit permit for the ERROR dispatch, the
 * chain's entry point rewrote it to 401 — so every 400, 429 and 503 the controllers raise reached
 * the client as "unauthorized".
 *
 * <p>That is not cosmetic: a rate-limited client would see an authentication failure and
 * re-prompt for a password instead of backing off, and a malformed request would look like bad
 * credentials. It also silently defeated the 429s added for the registration and origin limiters.
 *
 * <p>Asserted over the wire on a real server. The permit can be deleted from the chain and every
 * other test in the repository still passes, which is why this one exists.
 */
@SpringBootTest(classes = HofmannTestApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorStatusPassthroughTest {

  @LocalServerPort
  private int port;

  private HttpClient httpClient;

  @BeforeEach
  void setUp() {
    httpClient = HttpClient.newHttpClient();
  }

  private int post(String path, String body) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("http://localhost:" + port + path))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return httpClient.send(request, HttpResponse.BodyHandlers.ofString()).statusCode();
  }

  private int get(String path) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("http://localhost:" + port + path))
        .GET()
        .build();
    return httpClient.send(request, HttpResponse.BodyHandlers.ofString()).statusCode();
  }

  @Test
  void malformedOprfRequestReturns400NotUnauthorized() throws Exception {
    assertThat(post("/oprf", "{}"))
        .as("a bad request must not be reported as an authentication failure")
        .isEqualTo(400);
  }

  @Test
  void malformedOpaqueAuthStartReturns400NotUnauthorized() throws Exception {
    assertThat(post("/opaque/auth/start", "{\"credentialIdentifier\":\"\"}")).isEqualTo(400);
  }

  @Test
  void unparseableBodyReturns400NotUnauthorized() throws Exception {
    assertThat(post("/opaque/auth/start", "not json at all")).isEqualTo(400);
  }

  /**
   * The ERROR permit must be bound to the error path. Permitting the ERROR dispatch to any path
   * would let an application that maps a custom error page at a protected controller serve that
   * controller's body to unauthenticated callers.
   */
  @Test
  void errorPathIsStillProtectedOnADirectRequest() throws Exception {
    assertThat(get("/error"))
        .as("permitting the ERROR dispatch must not permit a direct request to /error")
        .isEqualTo(401);
  }

  @Test
  void protectedEndpointStillRequiresAToken() throws Exception {
    assertThat(get("/api/whoami")).isEqualTo(401);
  }
}
