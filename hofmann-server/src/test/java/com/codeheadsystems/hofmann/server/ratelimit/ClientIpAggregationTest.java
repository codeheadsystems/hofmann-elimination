package com.codeheadsystems.hofmann.server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A single IPv6 /64 — the standard allocation for one subscriber line — contains 2^64 addresses.
 * Keying a rate limiter on the full address therefore lets one host mint an unbounded number of
 * distinct keys, which both defeats the limit and, on a map-backed limiter, fills it.
 */
class ClientIpAggregationTest {

  @Test
  void addressesInOneIpv6PrefixShareAKey() {
    String a = ClientIpResolver.resolve(null, "2001:db8:1234:5678::1", false);
    String b = ClientIpResolver.resolve(null, "2001:db8:1234:5678:ffff:ffff:ffff:ffff", false);

    assertThat(a)
        .as("one subscriber line must not yield 2^64 distinct rate-limit keys")
        .isEqualTo(b);
  }

  @Test
  void differentIpv6PrefixesRemainDistinct() {
    assertThat(ClientIpResolver.resolve(null, "2001:db8:1111:1111::1", false))
        .isNotEqualTo(ClientIpResolver.resolve(null, "2001:db8:2222:2222::1", false));
  }

  /** IPv4 addresses are scarce enough that one address is already a meaningful unit. */
  @ParameterizedTest
  @ValueSource(strings = {"203.0.113.1", "198.51.100.20", "10.0.0.1"})
  void ipv4AddressesArePreservedExactly(String address) {
    assertThat(ClientIpResolver.resolve(null, address, false)).isEqualTo(address);
  }

  @Test
  void adjacentIpv4AddressesRemainDistinct() {
    assertThat(ClientIpResolver.resolve(null, "203.0.113.1", false))
        .isNotEqualTo(ClientIpResolver.resolve(null, "203.0.113.2", false));
  }

  @Test
  void bracketedAndPortedFormsNormaliseToTheSamePrefix() {
    String plain = ClientIpResolver.resolve(null, "2001:db8:1234:5678::1", false);
    assertThat(ClientIpResolver.resolve(null, "[2001:db8:1234:5678::1]:443", false))
        .isEqualTo(plain);
  }

  /** A link-local zone index is host-local and not part of the caller's identity. */
  @Test
  void zoneIndexIsIgnored() {
    assertThat(ClientIpResolver.resolve(null, "fe80::1%eth0", false))
        .isEqualTo(ClientIpResolver.resolve(null, "fe80::1%eth1", false));
  }

  @Test
  void aggregationAlsoAppliesToATrustedProxyHeader() {
    String a = ClientIpResolver.resolve("evil, 2001:db8:aaaa:bbbb::1", "10.0.0.1", true);
    String b = ClientIpResolver.resolve("evil, 2001:db8:aaaa:bbbb::2", "10.0.0.1", true);

    assertThat(a)
        .as("a forwarded address must be aggregated too, or the limiter is bypassed via the proxy")
        .isEqualTo(b);
  }

  @Test
  void unparseableValuesArePassedThroughRatherThanInvented() {
    assertThat(ClientIpResolver.resolve(null, "not-an-address", false)).isEqualTo("not-an-address");
  }
}
