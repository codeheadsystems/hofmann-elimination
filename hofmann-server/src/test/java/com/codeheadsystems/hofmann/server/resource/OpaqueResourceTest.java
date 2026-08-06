package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import java.util.concurrent.atomic.AtomicInteger;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

/**
 * Verifies that {@link OpaqueResource} maps the {@link HofmannOpaqueServerManager} exception
 * contract onto the correct JAX-RS HTTP status codes, and that {@code extractBearerToken}
 * strips the {@code "Bearer "} prefix.
 *
 * <p>Mirrors {@code OprfResourceTest}: the test classpath has only the JAX-RS API (no
 * container), so a mock {@link RuntimeDelegate} is installed. Unlike the OPRF test, this one
 * records the status passed to the response builder so each distinct mapping
 * (400/401/404/429/503) can be asserted independently. The manager is mocked and ignores its
 * request argument, so {@code null} requests are passed (the request records are final and not
 * mockable without inline mock-maker).
 */
class OpaqueResourceTest {

  private static final AtomicInteger LAST_STATUS = new AtomicInteger(-1);

  private HofmannOpaqueServerManager manager;
  private OpaqueResource resource;

  /**
   * Installs a mock {@link RuntimeDelegate} whose response builder records the status code so
   * that {@code WebApplicationException.getResponse().getStatus()} reflects the actual mapping.
   */
  @BeforeAll
  static void installRuntimeDelegate() {
    RuntimeDelegate mockRd = mock(RuntimeDelegate.class);
    Response.ResponseBuilder mockBuilder = mock(Response.ResponseBuilder.class, Mockito.RETURNS_SELF);
    Response mockResponse = mock(Response.class);

    when(mockRd.createResponseBuilder()).thenReturn(mockBuilder);
    when(mockBuilder.status(anyInt())).thenAnswer(inv -> {
      LAST_STATUS.set(inv.getArgument(0));
      return mockBuilder;
    });
    when(mockBuilder.status(anyInt(), nullable(String.class))).thenAnswer(inv -> {
      LAST_STATUS.set(inv.getArgument(0));
      return mockBuilder;
    });
    when(mockBuilder.status(any(Response.StatusType.class))).thenAnswer(inv -> {
      LAST_STATUS.set(((Response.StatusType) inv.getArgument(0)).getStatusCode());
      return mockBuilder;
    });
    when(mockBuilder.build()).thenReturn(mockResponse);
    when(mockResponse.getStatus()).thenAnswer(inv -> LAST_STATUS.get());
    // WebApplicationException(Response) and (StatusType) constructors derive their message from
    // getStatusInfo(); return a real Status so message computation does not NPE.
    when(mockResponse.getStatusInfo())
        .thenAnswer(inv -> Response.Status.fromStatusCode(LAST_STATUS.get()));

    RuntimeDelegate.setInstance(mockRd);
  }

  @AfterAll
  static void removeRuntimeDelegate() {
    RuntimeDelegate.setInstance(null);
  }

  @BeforeEach
  void setUp() {
    manager = mock(HofmannOpaqueServerManager.class);
    resource = new OpaqueResource(manager,
        new OpaqueClientConfigResponse("P256_SHA256", "context", 0, 0, 0));
    LAST_STATUS.set(-1);
  }

  /** Asserts the callable throws a {@link WebApplicationException} carrying {@code expectedStatus}. */
  private static void assertStatus(ThrowingCallable callable, int expectedStatus) {
    assertThatThrownBy(callable)
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(expectedStatus));
  }

  // ── authStart ──────────────────────────────────────────────────────────────

  @Test
  void authStart_illegalState_mapsTo503() {
    when(manager.authStart(any())).thenThrow(new IllegalStateException("Too many pending sessions"));
    assertStatus(() -> resource.authStart(null, null),
        Response.Status.SERVICE_UNAVAILABLE.getStatusCode());
  }

  @Test
  void authStart_rateLimit_mapsTo429() {
    when(manager.authStart(any())).thenThrow(new RateLimitExceededException());
    assertStatus(() -> resource.authStart(null, null), 429);
  }

  @Test
  void authStart_illegalArgument_mapsTo400() {
    when(manager.authStart(any())).thenThrow(new IllegalArgumentException("bad"));
    assertStatus(() -> resource.authStart(null, null), Response.Status.BAD_REQUEST.getStatusCode());
  }

  // ── authFinish ─────────────────────────────────────────────────────────────

  @Test
  void authFinish_securityException_mapsTo401() {
    when(manager.authFinish(any())).thenThrow(new SecurityException("Session not found or expired"));
    assertStatus(() -> resource.authFinish(null, null), Response.Status.UNAUTHORIZED.getStatusCode());
  }

  @Test
  void authFinish_illegalArgument_mapsTo400() {
    when(manager.authFinish(any())).thenThrow(new IllegalArgumentException("bad"));
    assertStatus(() -> resource.authFinish(null, null), Response.Status.BAD_REQUEST.getStatusCode());
  }

  // ── registrationFinish ─────────────────────────────────────────────────────

  @Test
  void registrationFinish_rateLimit_mapsTo429() {
    Mockito.doThrow(new RateLimitExceededException()).when(manager).registrationFinish(any(), any());
    assertStatus(() -> resource.registrationFinish(null, null, null), 429);
  }

  @Test
  void registrationFinish_securityException_mapsTo401() {
    Mockito.doThrow(new SecurityException("Invalid or expired recovery token"))
        .when(manager).registrationFinish(any(), any());
    assertStatus(() -> resource.registrationFinish(null, null, null),
        Response.Status.UNAUTHORIZED.getStatusCode());
  }

  @Test
  void registrationFinish_illegalArgument_mapsTo400() {
    // Any IllegalArgumentException must map to 400. Uses a validation-shaped message on
    // purpose: registrationFinish no longer throws on an already-registered credential — it
    // returns 204 so the response cannot be used to enumerate accounts.
    Mockito.doThrow(new IllegalArgumentException("Missing required field: credentialIdentifier"))
        .when(manager).registrationFinish(any(), any());
    assertStatus(() -> resource.registrationFinish(null, null, null),
        Response.Status.BAD_REQUEST.getStatusCode());
  }

  // ── registrationDelete ─────────────────────────────────────────────────────

  @Test
  void registrationDelete_securityException_mapsTo401() {
    Mockito.doThrow(new SecurityException("Authentication failed"))
        .when(manager).registrationDelete(any(), any());
    assertStatus(() -> resource.registrationDelete(null, null),
        Response.Status.UNAUTHORIZED.getStatusCode());
  }

  // ── recovery endpoints ─────────────────────────────────────────────────────

  @Test
  void recoveryStart_recoveryDisabled_mapsTo404() {
    Mockito.doThrow(new UnsupportedOperationException("Account recovery is not configured"))
        .when(manager).recoveryStart(any());
    assertStatus(() -> resource.recoveryStart(null, null), Response.Status.NOT_FOUND.getStatusCode());
  }

  @Test
  void recoveryStart_rateLimit_mapsTo429() {
    Mockito.doThrow(new RateLimitExceededException()).when(manager).recoveryStart(any());
    assertStatus(() -> resource.recoveryStart(null, null), 429);
  }

  @Test
  void recoveryVerify_recoveryDisabled_mapsTo404() {
    when(manager.recoveryVerify(any()))
        .thenThrow(new UnsupportedOperationException("Account recovery is not configured"));
    assertStatus(() -> resource.recoveryVerify(null, null), Response.Status.NOT_FOUND.getStatusCode());
  }

  @Test
  void recoveryVerify_securityException_mapsTo401() {
    when(manager.recoveryVerify(any())).thenThrow(new SecurityException("Recovery verification failed"));
    assertStatus(() -> resource.recoveryVerify(null, null), Response.Status.UNAUTHORIZED.getStatusCode());
  }

  // ── changePassword ─────────────────────────────────────────────────────────

  @Test
  void changePasswordStart_securityException_mapsTo401() {
    when(manager.changePasswordStart(any(), any()))
        .thenThrow(new SecurityException("Authentication failed"));
    assertStatus(() -> resource.changePasswordStart(null, null),
        Response.Status.UNAUTHORIZED.getStatusCode());
  }

  @Test
  void changePasswordStart_rateLimit_mapsTo429() {
    when(manager.changePasswordStart(any(), any())).thenThrow(new RateLimitExceededException());
    assertStatus(() -> resource.changePasswordStart(null, null), 429);
  }

  // ── extractBearerToken ─────────────────────────────────────────────────────

  @Test
  void extractBearerToken_stripsBearerPrefix() {
    when(manager.registrationStart(any(), any()))
        .thenReturn(new RegistrationStartResponse(new RegistrationResponse(new byte[33], new byte[33])));
    ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

    resource.registrationStart(null, "Bearer my-secret-token", null);

    Mockito.verify(manager).registrationStart(any(), tokenCaptor.capture());
    assertThat(tokenCaptor.getValue()).isEqualTo("my-secret-token");
  }

  @Test
  void extractBearerToken_nonBearerHeaderYieldsNull() {
    when(manager.registrationStart(any(), nullable(String.class)))
        .thenReturn(new RegistrationStartResponse(new RegistrationResponse(new byte[33], new byte[33])));

    resource.registrationStart(null, "Basic abc", null);

    Mockito.verify(manager).registrationStart(any(), eq((String) null));
  }
}
