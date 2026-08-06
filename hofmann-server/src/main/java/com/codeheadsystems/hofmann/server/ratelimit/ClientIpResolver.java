package com.codeheadsystems.hofmann.server.ratelimit;

/**
 * Resolves the rate-limiting key for a request's origin.
 *
 * <p>Shared so that the OPRF and OPAQUE endpoints, in both frameworks, cannot drift apart on the
 * one decision that determines whether an IP-keyed limiter is worth anything at all: whether to
 * believe {@code X-Forwarded-For}.
 *
 * <p>The credential-identifier-keyed limiters bound repeated attempts against a single account.
 * They do nothing against an attacker who varies the identifier, because every distinct value
 * gets its own fresh bucket — which is also what lets a flood exhaust the bucket map and the
 * pending-session store. Bounding by origin is the missing dimension, and it only works if the
 * key cannot be forged.
 */
public final class ClientIpResolver {

  /** Used when no origin can be determined, e.g. a unit test constructing a resource directly. */
  public static final String UNKNOWN = "unknown";

  private ClientIpResolver() {
  }

  /**
   * Chooses the origin key for a request.
   *
   * @param forwardedForHeader   the raw {@code X-Forwarded-For} value, or null
   * @param remoteAddress        the socket peer address, or null when unavailable
   * @param trustForwardedHeader whether the deployment sits behind a trusted proxy
   * @return a stable key for the request's origin
   */
  public static String resolve(final String forwardedForHeader,
                               final String remoteAddress,
                               final boolean trustForwardedHeader) {
    // Only honour X-Forwarded-For when explicitly told we are behind a trusted proxy. Otherwise
    // the header is fully attacker-controlled, and rotating it per request would mint a fresh
    // bucket every time — leaving the limiter strictly worse than useless, since it would also
    // fill the bucket map.
    if (trustForwardedHeader) {
      String forwarded = rightmostForwardedFor(forwardedForHeader);
      if (forwarded != null) {
        return forwarded;
      }
    }
    if (remoteAddress != null && !remoteAddress.isBlank()) {
      return remoteAddress;
    }
    // Never fall back to the spoofable header here.
    return UNKNOWN;
  }

  /**
   * Returns the right-most entry of an {@code X-Forwarded-For} header, or {@code null} if absent.
   *
   * <p>The right-most entry is the address appended by the immediate (trusted) proxy and is the
   * only value an external client cannot forge: proxies that <em>append</em> to XFF — the common
   * default, e.g. HAProxy {@code option forwardfor} — place attacker-supplied values to the left,
   * so taking the left-most entry would let a client choose its own rate-limit key even in
   * trusted-proxy mode.
   *
   * @param header the raw header value, or null
   * @return the right-most entry, or null
   */
  public static String rightmostForwardedFor(final String header) {
    if (header == null || header.isBlank()) {
      return null;
    }
    String[] parts = header.split(",");
    for (int i = parts.length - 1; i >= 0; i--) {
      String candidate = parts[i].trim();
      if (!candidate.isEmpty()) {
        return candidate;
      }
    }
    return null;
  }
}
