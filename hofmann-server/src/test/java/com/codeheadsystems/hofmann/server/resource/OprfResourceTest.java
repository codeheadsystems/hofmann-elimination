package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The type Oprf resource test.
 */
@ExtendWith(MockitoExtension.class)
class OprfResourceTest {

  private static final String EC_POINT = "03abcdef1234567890";
  private static final String REQUEST_ID = "req-001";
  private static final String PROCESS_ID = "proc-xyz";
  private static final String EVALUATED_POINT = "02fedcba0987654321";
  @Mock private OprfServerManager oprfServerManager;
  @Mock private RateLimiter rateLimiter;
  @Mock private ContainerRequestContext ctx;
  private OprfResource resource;

  private static final java.util.concurrent.atomic.AtomicInteger LAST_STATUS =
      new java.util.concurrent.atomic.AtomicInteger(-1);

  /**
   * Install runtime delegate.
   */
  @BeforeAll
  static void installRuntimeDelegate() {
    // WebApplicationException constructor requires a JAX-RS RuntimeDelegate implementation.
    // Since tests only have the API jar (no container), we install a mock delegate so that
    // WebApplicationException can be constructed and its HTTP status can be verified. The mock
    // records the status passed to the builder so both 400 and 429 mappings can be asserted.
    RuntimeDelegate mockRd = mock(RuntimeDelegate.class);
    Response.ResponseBuilder mockBuilder = mock(Response.ResponseBuilder.class, Mockito.RETURNS_SELF);
    Response mockResponse = mock(Response.class);

    when(mockRd.createResponseBuilder()).thenReturn(mockBuilder);
    when(mockBuilder.status(anyInt())).thenAnswer(inv -> {
      LAST_STATUS.set(inv.getArgument(0));
      return mockBuilder;
    });
    when(mockBuilder.status(anyInt(), Mockito.nullable(String.class))).thenAnswer(inv -> {
      LAST_STATUS.set(inv.getArgument(0));
      return mockBuilder;
    });
    when(mockBuilder.status(Mockito.any(Response.StatusType.class))).thenAnswer(inv -> {
      LAST_STATUS.set(((Response.StatusType) inv.getArgument(0)).getStatusCode());
      return mockBuilder;
    });
    when(mockBuilder.build()).thenReturn(mockResponse);
    when(mockResponse.getStatus()).thenAnswer(inv -> LAST_STATUS.get());
    // WebApplicationException(Response) derives its message from getStatusInfo(); return a real
    // Status so message computation does not NPE on the rate-limit (429) path.
    when(mockResponse.getStatusInfo())
        .thenAnswer(inv -> Response.Status.fromStatusCode(LAST_STATUS.get()));

    RuntimeDelegate.setInstance(mockRd);
  }

  /**
   * Remove runtime delegate.
   */
  @AfterAll
  static void removeRuntimeDelegate() {
    RuntimeDelegate.setInstance(null);
  }

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    // lenient: the rate-limit-exceeded test re-stubs tryConsume to return false.
    Mockito.lenient().when(rateLimiter.tryConsume(anyString())).thenReturn(true);
    resource = new OprfResource(oprfServerManager, new OprfClientConfigResponse("P256_SHA256"), rateLimiter);
  }

  /**
   * Evaluate valid request returns oprf response.
   */
  @Test
  void evaluate_validRequest_returnsOprfResponse() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);
    EvaluatedResponse evaluatedResponse = new EvaluatedResponse(EVALUATED_POINT, PROCESS_ID);
    when(oprfServerManager.process(request.blindedRequest())).thenReturn(evaluatedResponse);

    OprfResponse response = resource.evaluate(request, ctx, null);

    assertThat(response.ecPoint()).isEqualTo(EVALUATED_POINT);
    assertThat(response.processIdentifier()).isEqualTo(PROCESS_ID);
  }

  /**
   * Evaluate null ec point throws bad request.
   */
  @Test
  void evaluate_nullEcPoint_throwsBadRequest() {
    OprfRequest request = new OprfRequest(null, REQUEST_ID);

    assertThatThrownBy(() -> resource.evaluate(request, ctx, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  /**
   * Evaluate blank ec point throws bad request.
   */
  @Test
  void evaluate_blankEcPoint_throwsBadRequest() {
    OprfRequest request = new OprfRequest("   ", REQUEST_ID);

    assertThatThrownBy(() -> resource.evaluate(request, ctx, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  /**
   * Evaluate null request id throws bad request.
   */
  @Test
  void evaluate_nullRequestId_throwsBadRequest() {
    OprfRequest request = new OprfRequest(EC_POINT, null);

    assertThatThrownBy(() -> resource.evaluate(request, ctx, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  /**
   * Evaluate blank request id throws bad request.
   */
  @Test
  void evaluate_blankRequestId_throwsBadRequest() {
    OprfRequest request = new OprfRequest(EC_POINT, "  ");

    assertThatThrownBy(() -> resource.evaluate(request, ctx, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  /**
   * Evaluate when rate limiter denies the request maps to HTTP 429.
   */
  @Test
  void evaluate_rateLimited_throwsTooManyRequests() {
    when(rateLimiter.tryConsume(anyString())).thenReturn(false);
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    assertThatThrownBy(() -> resource.evaluate(request, ctx, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(429));
  }

  /**
   * When trusting forwarded headers, the rate-limit key is the right-most (proxy-appended)
   * X-Forwarded-For entry, not the left-most attacker-supplied one.
   */
  @Test
  void evaluate_trustForwardedHeaders_usesRightmostXffEntry() {
    OprfResource trusting = new OprfResource(
        oprfServerManager, new OprfClientConfigResponse("P256_SHA256"), rateLimiter, true);
    // A client spoofs "1.1.1.1"; the trusted proxy appends the real peer "7.7.7.7" on the right.
    when(ctx.getHeaderString("X-Forwarded-For")).thenReturn("1.1.1.1, 8.8.8.8, 7.7.7.7");
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);
    when(oprfServerManager.process(request.blindedRequest()))
        .thenReturn(new EvaluatedResponse(EVALUATED_POINT, PROCESS_ID));

    trusting.evaluate(request, ctx, null);

    ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
    verify(rateLimiter).tryConsume(key.capture());
    assertThat(key.getValue()).isEqualTo("7.7.7.7");
  }

  /**
   * Evaluate illegal argument from server manager throws bad request.
   */
  @Test
  void evaluate_illegalArgumentFromServerManager_throwsBadRequest() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);
    when(oprfServerManager.process(request.blindedRequest()))
        .thenThrow(new IllegalArgumentException("bad point"));

    assertThatThrownBy(() -> resource.evaluate(request, ctx, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }
}
