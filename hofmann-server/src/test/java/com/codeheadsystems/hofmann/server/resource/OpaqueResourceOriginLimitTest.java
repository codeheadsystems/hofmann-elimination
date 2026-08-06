package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * An origin-keyed limiter is only meaningful if it actually sees the origin.
 *
 * <p>The first version of this feature read the request from a {@code @Context}-injected field on
 * this singleton resource. That silently yields null, so every caller resolved to one constant
 * key and the limiter became a single global bucket — any one client could drain it and deny all
 * six endpoints for the whole deployment, which is strictly worse than having no limiter. Nothing
 * caught it, because no test passed two different origins.
 */
class OpaqueResourceOriginLimitTest {

  private static final OpaqueClientConfigResponse CONFIG =
      new OpaqueClientConfigResponse("P256_SHA256", "ctx", 65536, 3, 1);

  private static AuthStartRequest request() {
    return new AuthStartRequest("YWxpY2U=", "AA==", "AA==", "AA==");
  }

  private static HttpServletRequest requestFrom(String remoteAddr, String forwardedFor) {
    HttpServletRequest http = mock(HttpServletRequest.class);
    when(http.getRemoteAddr()).thenReturn(remoteAddr);
    when(http.getHeader("X-Forwarded-For")).thenReturn(forwardedFor);
    return http;
  }

  /** The regression test: two peers must land in two buckets. */
  @Test
  void distinctPeersAreKeyedSeparately() {
    List<String> keys = new ArrayList<>();
    RateLimiter recording = key -> {
      keys.add(key);
      return true;
    };
    HofmannOpaqueServerManager manager = mock(HofmannOpaqueServerManager.class);
    OpaqueResource resource = new OpaqueResource(manager, CONFIG, recording, false);

    resource.authStart(request(), requestFrom("203.0.113.1", null));
    resource.authStart(request(), requestFrom("203.0.113.2", null));

    assertThat(keys)
        .as("each origin must get its own bucket; one shared key means one global limit")
        .containsExactly("203.0.113.1", "203.0.113.2");
  }

  @Test
  void spoofedForwardedHeaderIsIgnoredWhenProxyIsNotTrusted() {
    List<String> keys = new ArrayList<>();
    RateLimiter recording = key -> {
      keys.add(key);
      return true;
    };
    OpaqueResource resource = new OpaqueResource(
        mock(HofmannOpaqueServerManager.class), CONFIG, recording, false);

    resource.authStart(request(), requestFrom("203.0.113.1", "1.2.3.4"));

    assertThat(keys)
        .as("honouring a spoofable header would let one client mint unlimited buckets")
        .containsExactly("203.0.113.1");
  }

  @Test
  void trustedProxyUsesTheRightmostForwardedEntry() {
    List<String> keys = new ArrayList<>();
    RateLimiter recording = key -> {
      keys.add(key);
      return true;
    };
    OpaqueResource resource = new OpaqueResource(
        mock(HofmannOpaqueServerManager.class), CONFIG, recording, true);

    resource.authStart(request(), requestFrom("10.0.0.1", "evil, evil, 198.51.100.20"));

    assertThat(keys).containsExactly("198.51.100.20");
  }

  /**
   * Asserts only that the request is rejected before reaching the manager. The 429 status itself
   * is pinned by OpaqueResourceTest, which covers the identical response construction on the
   * manager-thrown rate-limit path; building a Response here would need a JAX-RS RuntimeDelegate
   * that this unit-scope test does not have.
   */
  @Test
  void exhaustedOriginIsRejectedBeforeReachingTheManager() {
    HofmannOpaqueServerManager manager = mock(HofmannOpaqueServerManager.class);
    OpaqueResource resource = new OpaqueResource(manager, CONFIG, key -> false, false);

    assertThatThrownBy(() -> resource.authStart(request(), requestFrom("203.0.113.1", null)))
        .isInstanceOf(RuntimeException.class);
    verify(manager, org.mockito.Mockito.never()).authStart(any());
  }

  /** With no limiter configured — the default — the endpoint must behave exactly as before. */
  @Test
  void noLimiterConfiguredIsANoOp() {
    HofmannOpaqueServerManager manager = mock(HofmannOpaqueServerManager.class);
    OpaqueResource resource = new OpaqueResource(manager, CONFIG);

    resource.authStart(request(), requestFrom("203.0.113.1", null));

    verify(manager).authStart(any());
  }
}
