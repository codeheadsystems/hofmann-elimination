package com.codeheadsystems.hofmann.server.ratelimit;

public interface RateLimitConfigSupplier {

  RateLimitConfig authRateLimitConfig();

  RateLimitConfig registrationRateLimitConfig();

  RateLimitConfig oprfRateLimitConfig();

  RateLimitConfig recoveryRateLimitConfig();

  /**
   * Limit applied per request origin across the unauthenticated OPAQUE endpoints, or {@code null}
   * to disable it. <strong>Disabled by default.</strong>
   *
   * <p>The other limiters key on the credential identifier, which bounds attempts against one
   * account and nothing else — an attacker who varies the identifier is unthrottled, which is how
   * a flood exhausts the bucket map and the pending-session store. Bounding by origin is the
   * missing dimension, but it is off by default because as a blanket default it does more harm
   * than good:
   *
   * <ul>
   *   <li><strong>It throttles real deployments.</strong> One login draws two tokens, so a limit
   *       of N per minute allows N/2 logins per minute for an entire origin. Behind a corporate
   *       NAT or mobile CGNAT that is one bucket for thousands of users, and a morning login peak
   *       will hit it.</li>
   *   <li><strong>It does not stop a determined attacker.</strong> The key is a single address
   *       with no prefix aggregation, so a distributed source — or one IPv6 /64 — sidesteps it
   *       entirely.</li>
   *   <li><strong>Its own bucket map is bounded the same way.</strong> Filling it denies every
   *       origin whose bucket is not resident, in front of all six endpoints, which reproduces
   *       the outage this was meant to prevent one layer earlier.</li>
   * </ul>
   *
   * <p>So it is a useful control for a deployment that knows its client-address distribution, and
   * a liability as a default. Operators who want it should override this method and size it for
   * their traffic. Properly bounding the key space — prefix aggregation and a fixed-size
   * structure that cannot be filled — is recorded as follow-up work in TODO.md; until then the
   * flood remains possible and pretending otherwise with a default-on limiter would be worse
   * than saying so.
   *
   * @return the origin rate limit config, or null to disable origin-based limiting
   */
  default RateLimitConfig originRateLimitConfig() {
    // Two tokens per login, so 600/min is 300 logins a minute from one origin. Sized to stay out
    // of the way of a corporate NAT or mobile CGNAT while still bounding a single source, now
    // that the key is aggregated to an IPv6 /64 rather than a bare address — a /64 is one
    // subscriber line, and keying on the full address let a single host mint 2^64 distinct keys.
    // maxEntries is unused: the origin limiter is backed by a fixed-capacity structure that
    // cannot be filled.
    return new RateLimitConfig(600, 600.0 / 60, 0);
  }


  class DefaultRateLimitConfigSupplier implements RateLimitConfigSupplier {

    @Override
    public RateLimitConfig recoveryRateLimitConfig() {
      // A full legitimate recovery draws three tokens from this bucket (recoveryStart +
      // recoveryVerify + registrationFinish); capacity 6 leaves headroom for a couple of
      // mistyped challenge codes while still tightly throttling online code/token guessing.
      return new RateLimitConfig(6, 6.0 / 60, 50_000);
    }

    @Override
    public RateLimitConfig authRateLimitConfig() {
      return new RateLimitConfig(10, 10.0 / 60, 50_000);
    }

    @Override
    public RateLimitConfig registrationRateLimitConfig() {
      return new RateLimitConfig(5, 5.0 / 60, 50_000);
    }

    @Override
    public RateLimitConfig oprfRateLimitConfig() {
      return new RateLimitConfig(30, 30.0 / 60, 50_000);
    }

  }

}
