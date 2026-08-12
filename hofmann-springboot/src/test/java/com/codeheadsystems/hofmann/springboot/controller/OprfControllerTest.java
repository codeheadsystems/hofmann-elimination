package com.codeheadsystems.hofmann.springboot.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.springboot.config.HofmannProperties;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests for {@link OprfController}'s client-IP extraction used as the rate-limit key.
 */
@ExtendWith(MockitoExtension.class)
class OprfControllerTest {

  @Mock private OprfServerManager oprfServerManager;
  @Mock private RateLimiter rateLimiter;
  @Mock private HttpServletRequest httpRequest;

  private OprfController controller(boolean trustForwardedHeaders) {
    // null verifiable managers: base-mode deployment, which is the default shape.
    HofmannProperties props = new HofmannProperties();
    props.setTrustForwardedHeaders(trustForwardedHeaders);
    return new OprfController(oprfServerManager, new OprfClientConfigResponse("P256_SHA256"),
        rateLimiter, props, null, null);
  }

  private OprfRequest validRequest() {
    OprfRequest request = new OprfRequest("03abcdef1234567890", "req-1");
    Mockito.lenient().when(rateLimiter.tryConsume(anyString())).thenReturn(true);
    when(oprfServerManager.process(request.blindedRequest()))
        .thenReturn(new EvaluatedResponse("02fedcba0987654321", "proc"));
    return request;
  }

  @Test
  void trustForwardedHeaders_usesRightmostXffEntry() {
    OprfRequest request = validRequest();
    // Client spoofs "1.1.1.1" on the left; the trusted proxy appends the real peer "7.7.7.7".
    when(httpRequest.getHeader("X-Forwarded-For")).thenReturn("1.1.1.1, 8.8.8.8, 7.7.7.7");

    controller(true).evaluate(request, httpRequest);

    ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
    verify(rateLimiter).tryConsume(key.capture());
    assertThat(key.getValue()).isEqualTo("7.7.7.7");
  }

  @Test
  void trustForwardedHeadersDisabled_ignoresXffAndUsesRemoteAddr() {
    OprfRequest request = validRequest();
    when(httpRequest.getRemoteAddr()).thenReturn("10.0.0.5");

    controller(false).evaluate(request, httpRequest);

    ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
    verify(rateLimiter).tryConsume(key.capture());
    assertThat(key.getValue()).isEqualTo("10.0.0.5");
  }

  @Test
  void trustForwardedHeaders_butHeaderAbsent_fallsBackToRemoteAddr() {
    OprfRequest request = validRequest();
    when(httpRequest.getHeader("X-Forwarded-For")).thenReturn(null);
    when(httpRequest.getRemoteAddr()).thenReturn("10.0.0.9");

    controller(true).evaluate(request, httpRequest);

    ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
    verify(rateLimiter).tryConsume(key.capture());
    assertThat(key.getValue()).isEqualTo("10.0.0.9");
  }

  // ── base-mode field bounds ─────────────────────────────────────────────────
  //
  // VOPRF and POPRF get their bounds from OprfWireFields on the wire model, so every adapter
  // shares one copy. Base mode does not: these four checks are written out here and again in the
  // JAX-RS OprfResource, each with its own MAX_EC_POINT_HEX_LENGTH and MAX_REQUEST_ID_LENGTH.
  // Duplicated limits drift, so both copies are now pinned — see OprfResourceTest for the other.

  @Test
  void evaluate_nullEcPoint_isBadRequest() {
    assertBadRequest(new OprfRequest(null, "req-1"));
  }

  @Test
  void evaluate_blankEcPoint_isBadRequest() {
    assertBadRequest(new OprfRequest("   ", "req-1"));
  }

  @Test
  void evaluate_oversizedEcPoint_isBadRequest() {
    assertBadRequest(new OprfRequest("a".repeat(4097), "req-1"));
  }

  @Test
  void evaluate_nullRequestId_isBadRequest() {
    assertBadRequest(new OprfRequest("03abcdef1234567890", null));
  }

  @Test
  void evaluate_blankRequestId_isBadRequest() {
    assertBadRequest(new OprfRequest("03abcdef1234567890", "   "));
  }

  @Test
  void evaluate_oversizedRequestId_isBadRequest() {
    assertBadRequest(new OprfRequest("03abcdef1234567890", "a".repeat(513)));
  }

  /**
   * Both limits are ceilings, not floors. Without an at-limit case, tightening either constant to
   * zero would leave every rejection test above green while refusing all legitimate traffic.
   */
  @Test
  void evaluate_fieldsExactlyAtTheLimit_areAccepted() {
    OprfRequest request = new OprfRequest("a".repeat(4096), "b".repeat(512));
    Mockito.lenient().when(rateLimiter.tryConsume(anyString())).thenReturn(true);
    when(oprfServerManager.process(request.blindedRequest()))
        .thenReturn(new EvaluatedResponse("02fedcba0987654321", "proc"));

    assertThat(controller(false).evaluate(request, httpRequest).ecPoint())
        .isEqualTo("02fedcba0987654321");
  }

  /**
   * Asserts the controller refuses the request with 400 before the crypto layer sees it. The
   * manager is deliberately left unstubbed: reaching it would surface as a Mockito failure rather
   * than a silent pass.
   */
  private void assertBadRequest(final OprfRequest request) {
    Mockito.lenient().when(rateLimiter.tryConsume(anyString())).thenReturn(true);

    assertThatThrownBy(() -> controller(false).evaluate(request, httpRequest))
        .isInstanceOf(ResponseStatusException.class)
        .extracting(e -> ((ResponseStatusException) e).getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);
    Mockito.verifyNoInteractions(oprfServerManager);
  }
}
