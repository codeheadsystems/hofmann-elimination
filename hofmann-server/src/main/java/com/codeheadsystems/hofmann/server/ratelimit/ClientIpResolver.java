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
 * draws on its own budget — which is what lets a flood reach the pending-session store unthrottled.
 * Bounding by origin is the missing dimension, and it only works if the key cannot be forged.
 *
 * <p>See {@code docs/adr/0002-origin-rate-limiting-on-by-default.md} for why the /64 aggregation
 * below is what made origin limiting viable as a default.
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
    // the header is fully attacker-controlled, and rotating it per request would draw on a fresh
    // budget every time — leaving the limiter useless against exactly the caller it is meant to
    // bound, while still charging honest ones.
    if (trustForwardedHeader) {
      String forwarded = rightmostForwardedFor(forwardedForHeader);
      if (forwarded != null) {
        return aggregate(forwarded);
      }
    }
    if (remoteAddress != null && !remoteAddress.isBlank()) {
      return aggregate(remoteAddress);
    }
    // Never fall back to the spoofable header here.
    return UNKNOWN;
  }

  /**
   * Collapses an address to the smallest unit an operator is plausibly allocated.
   *
   * <p>IPv6 is aggregated to the /64 prefix. A single IPv6 /64 — the standard allocation for one
   * subscriber line — contains 2^64 addresses, so keying on the full address lets one host mint
   * an unbounded number of distinct rate-limit keys. That defeats the limiter outright, and on a
   * map-backed one fills it. IPv4 is returned unchanged: addresses there are scarce enough that
   * a single one is a meaningful unit, and aggregating to a /24 would lump unrelated networks
   * together.
   *
   * @param address a client address, or a value from a trusted proxy header
   * @return the aggregated key
   */
  static String aggregate(final String address) {
    String candidate = address.trim();
    // Strip a bracketed form and any port: [2001:db8::1]:443
    if (candidate.startsWith("[")) {
      int close = candidate.indexOf(']');
      if (close > 0) {
        candidate = candidate.substring(1, close);
      }
    }
    if (candidate.indexOf(':') < 0) {
      return candidate; // IPv4, or a hostname — leave alone
    }
    // Zone index (fe80::1%eth0) is host-local and not part of the identity.
    int zone = candidate.indexOf('%');
    if (zone > 0) {
      candidate = candidate.substring(0, zone);
    }
    try {
      byte[] bytes = java.net.InetAddress.getByName(candidate).getAddress();
      if (bytes.length != 16) {
        return candidate; // IPv4-mapped or otherwise not a v6 address
      }
      StringBuilder prefix = new StringBuilder(20);
      for (int i = 0; i < 8; i += 2) {
        if (i > 0) {
          prefix.append(':');
        }
        prefix.append(String.format("%02x%02x", bytes[i], bytes[i + 1]));
      }
      return prefix.append("::/64").toString();
    } catch (java.net.UnknownHostException e) {
      // Not parseable as an address; use it verbatim rather than inventing a key.
      return candidate;
    }
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
