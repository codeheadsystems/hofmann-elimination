package com.codeheadsystems.hofmann.server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * An origin-keyed limiter is worth exactly as much as the forgeability of its key. If a client
 * can choose its own key it gets unlimited buckets — and fills the bucket map while doing it,
 * which is worse than having no limiter at all.
 */
class ClientIpResolverTest {

  private static final String PEER = "198.51.100.20";

  // ── Untrusted (the default) ────────────────────────────────────────────────

  @Test
  void untrustedDeploymentIgnoresForwardedHeaderEntirely() {
    assertThat(ClientIpResolver.resolve("9.9.9.9", PEER, false)).isEqualTo(PEER);
    assertThat(ClientIpResolver.resolve("1.1.1.1, 2.2.2.2, 3.3.3.3", PEER, false)).isEqualTo(PEER);
  }

  @Test
  void untrustedDeploymentWithNoSocketAddressDoesNotFallBackToTheHeader() {
    assertThat(ClientIpResolver.resolve("9.9.9.9", null, false))
        .as("falling back to a spoofable header would let a client mint unlimited buckets")
        .isEqualTo(ClientIpResolver.UNKNOWN);
  }

  // ── Trusted proxy ─────────────────────────────────────────────────────────

  @Test
  void trustedDeploymentTakesTheRightmostEntry() {
    // A proxy that appends puts the attacker's value to the LEFT. Taking the left-most entry
    // would let a client choose its own key even behind a trusted proxy.
    assertThat(ClientIpResolver.resolve("evil, evil, evil, " + PEER, "10.0.0.1", true))
        .isEqualTo(PEER);
  }

  @Test
  void trustedDeploymentFallsBackToSocketWhenHeaderIsAbsentOrBlank() {
    assertThat(ClientIpResolver.resolve(null, PEER, true)).isEqualTo(PEER);
    assertThat(ClientIpResolver.resolve("", PEER, true)).isEqualTo(PEER);
    assertThat(ClientIpResolver.resolve("   ", PEER, true)).isEqualTo(PEER);
    assertThat(ClientIpResolver.resolve(" , , ", PEER, true)).isEqualTo(PEER);
  }

  @Test
  void trailingCommaDoesNotYieldAnEmptyKey() {
    assertThat(ClientIpResolver.resolve(PEER + ", ", "10.0.0.1", true)).isEqualTo(PEER);
  }

  /**
   * IPv6 is aggregated to the /64 prefix rather than passed through — a single /64 is one
   * subscriber line and contains 2^64 addresses, so keying on the full address would let one host
   * mint unlimited rate-limit keys. Prefix behaviour is covered in detail by
   * {@link ClientIpAggregationTest}; asserted here so the resolver's own contract stays explicit.
   */
  @Test
  void ipv6AddressesAreAggregatedToTheirPrefix() {
    String prefix = ClientIpResolver.resolve(null, "2001:db8::1", false);

    assertThat(prefix).isEqualTo("2001:0db8:0000:0000::/64");
    assertThat(ClientIpResolver.resolve("evil, 2001:db8::1", "10.0.0.1", true)).isEqualTo(prefix);
  }

  // ── Degenerate input ──────────────────────────────────────────────────────

  @Test
  void noRequestContextYieldsTheUnknownKeyRatherThanNull() {
    assertThat(ClientIpResolver.resolve(null, null, false)).isEqualTo(ClientIpResolver.UNKNOWN);
    assertThat(ClientIpResolver.resolve(null, "", true)).isEqualTo(ClientIpResolver.UNKNOWN);
  }

  /**
   * The failure this pins is not hypothetical: {@code @Context} field injection into a singleton
   * JAX-RS resource silently yields null, so every caller resolved to this one constant and the
   * "per-origin" limiter became a single global bucket that any one client could drain to deny
   * the whole deployment. Callers must thread the request in explicitly.
   */
  @Test
  void everyOriginCollapsesToOneKeyWhenTheRequestIsMissing() {
    String a = ClientIpResolver.resolve(null, null, false);
    String b = ClientIpResolver.resolve("1.2.3.4", null, false);
    assertThat(a)
        .as("a null request cannot distinguish callers — a limiter keyed on this is global")
        .isEqualTo(b);
  }

  @Test
  void distinctPeersProduceDistinctKeys() {
    assertThat(ClientIpResolver.resolve(null, "203.0.113.1", false))
        .isNotEqualTo(ClientIpResolver.resolve(null, "203.0.113.2", false));
  }
}
