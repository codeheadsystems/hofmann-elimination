package com.codeheadsystems.hofmann.springboot.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
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
    return new OprfController(oprfServerManager, new OprfClientConfigResponse("P256_SHA256"),
        rateLimiter, trustForwardedHeaders, null, null);
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
}
