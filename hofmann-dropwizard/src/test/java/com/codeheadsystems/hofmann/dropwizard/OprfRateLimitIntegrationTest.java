package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Integration test for the OPRF rate limiter's per-client keying, exercised end-to-end through
 * the real Jersey/Jetty request pipeline (not a mocked resource).
 * <p>
 * The server is configured with {@code trustForwardedHeaders: true}. Each simulated client sends
 * the same left-most {@code X-Forwarded-For} value but a distinct right-most value, mimicking a
 * trusted proxy that appends the real peer address. This verifies two properties at once:
 * <ul>
 *   <li>the rate-limit key is derived per request through the live container (so a client cannot
 *       exhaust another client's bucket), and</li>
 *   <li>the key is the <em>right-most</em> (proxy-appended) entry — if the left-most entry were
 *       used, both clients would share a bucket and the second client would be throttled.</li>
 * </ul>
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class OprfRateLimitIntegrationTest {

  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config-trust-xff.yml"));

  // A spoofed left-most entry shared by both clients; the trusted proxy appends the real peer.
  private static final String SPOOFED_LEFT = "10.0.0.99";
  private static final String CLIENT_A_XFF = SPOOFED_LEFT + ", 203.0.113.1";
  private static final String CLIENT_B_XFF = SPOOFED_LEFT + ", 203.0.113.2";

  // Well-formed OprfRequest JSON. The rate limiter is consumed before crypto validation, so the
  // (invalid) point only affects the non-429 status, never whether a token is drawn.
  private static final String BODY = "{\"ecPoint\":\"03\",\"requestId\":\"r\"}";

  private final HttpClient http = HttpClient.newHttpClient();

  @Test
  void rateLimitBuckets_areKeyedByRightmostForwardedFor() throws Exception {
    // Exhaust client A's bucket. Capacity is bounded (default 30); cap the loop well above it.
    int aStatusWhenThrottled = -1;
    int sentBeforeThrottle = 0;
    for (int i = 0; i < 200; i++) {
      int status = postOprf(CLIENT_A_XFF);
      if (status == 429) {
        aStatusWhenThrottled = 429;
        break;
      }
      assertThat(status).as("pre-throttle responses are not 429").isNotEqualTo(429);
      sentBeforeThrottle++;
    }
    assertThat(aStatusWhenThrottled)
        .as("client A's bucket should eventually be exhausted with HTTP 429")
        .isEqualTo(429);
    assertThat(sentBeforeThrottle)
        .as("the bucket should allow a burst before throttling")
        .isGreaterThan(0);

    // Client B shares A's left-most XFF entry but has a distinct right-most entry: it must have
    // its own bucket and therefore must NOT be throttled.
    assertThat(postOprf(CLIENT_B_XFF))
        .as("client B (distinct right-most XFF) must have an independent bucket")
        .isNotEqualTo(429);

    // Client A remains throttled.
    assertThat(postOprf(CLIENT_A_XFF))
        .as("client A stays throttled after exhausting its bucket")
        .isEqualTo(429);
  }

  private int postOprf(String forwardedFor) throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl() + "/oprf"))
        .header("Content-Type", "application/json")
        .header("X-Forwarded-For", forwardedFor)
        .POST(HttpRequest.BodyPublishers.ofString(BODY))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }
}
