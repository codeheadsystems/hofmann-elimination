package com.codeheadsystems.hofmann.server.ratelimit;

/**
 * Supplies the token-bucket sizing for each rate-limited endpoint group. The framework adapters
 * call this once at wiring time and hand each config to a {@link FixedCapacityRateLimiter}, so the
 * values here are read at startup and not re-consulted per request.
 *
 * <p>Implement this interface to size the limits for your traffic;
 * {@link DefaultRateLimitConfigSupplier} provides conservative defaults for the four required
 * methods and inherits the default-off {@link #originRateLimitConfig()}.
 *
 * <p>The four required limiters key on a value the caller supplies — a credential identifier or a
 * client address — so each bounds attempts against one account or one origin, not overall request
 * volume. See {@link #originRateLimitConfig()} for the cross-cutting bound and what it does and
 * does not buy you.
 */
public interface RateLimitConfigSupplier {

  /**
   * Limit applied per credential identifier across the OPAQUE authentication endpoints. This is
   * the bound on online password guessing against a single account, so it should be the tightest
   * of the four.
   *
   * @return the authentication rate limit config; must not be null
   */
  RateLimitConfig authRateLimitConfig();

  /**
   * Limit applied per credential identifier across the OPAQUE registration endpoints. Bounds how
   * fast one identifier can be registered or re-registered.
   *
   * @return the registration rate limit config; must not be null
   */
  RateLimitConfig registrationRateLimitConfig();

  /**
   * Limit applied per client address to the standalone OPRF endpoint. Unlike the OPAQUE limiters
   * this one has no credential to key on, so it keys on the resolved client address — see
   * {@link ClientIpResolver} for how that is derived and aggregated.
   *
   * @return the OPRF rate limit config; must not be null
   */
  RateLimitConfig oprfRateLimitConfig();

  /**
   * Limit applied across the account-recovery endpoints, keyed on the challenge id when the
   * request presents one this server issued for the credential it names, and on the credential
   * identifier otherwise. This is the bound on guessing a recovery code, so a full legitimate
   * recovery must fit inside it: it draws three tokens (start, verify, then registration finish).
   *
   * @return the recovery rate limit config; must not be null
   */
  RateLimitConfig recoveryRateLimitConfig();

  /**
   * Limit applied per request origin across the unauthenticated OPAQUE endpoints, or {@code null}
   * to disable it. <strong>Disabled by default.</strong>
   *
   * <p><strong>Enable it if you enable account recovery.</strong> It is the only global bound on
   * {@code recoveryStart}, which is unauthenticated and whose own limiter keys on the credential
   * identifier — a value an attacker varies freely. Without it, the capacity policy in
   * {@code InMemoryRecoveryChallengeStore} is the only thing bounding a flood, which is a last
   * line rather than a first. See {@code RECOVERY.md}.
   *
   * <p>The other limiters key on the credential identifier, which bounds attempts against one
   * account and nothing else — an attacker who varies the identifier is unthrottled, and reaches
   * the pending-session store at whatever rate they can send. Bounding by origin is the missing
   * dimension, but it is off by default because as a blanket default it does more harm than good:
   *
   * <ul>
   *   <li><strong>It throttles real deployments.</strong> One login draws two tokens, so a limit
   *       of N per minute allows N/2 logins per minute for an entire origin. Behind a corporate
   *       NAT or mobile CGNAT that is one bucket for thousands of users, and a morning login peak
   *       will hit it.</li>
   *   <li><strong>It does not stop a determined attacker.</strong> IPv6 keys are aggregated to the
   *       /64 — one subscriber line, rather than the 2^64 distinct keys a bare address allowed —
   *       but a distributed source, or an attacker holding more than one prefix, still sidesteps
   *       it.</li>
   *   <li><strong>It buys precision, not certainty.</strong> The limiter behind it is a
   *       {@link FixedCapacityRateLimiter}, so its memory is fixed and it cannot be exhausted by
   *       varying the key; the cost is that distinct origins can share a slot and therefore a
   *       budget. An origin denied by a neighbour's traffic is denied in front of all six
   *       endpoints.</li>
   * </ul>
   *
   * <p>So it is a useful control for a deployment that knows its client-address distribution, and
   * a liability as a default. Operators who want it should override this method and size it for
   * their traffic.
   *
   * @return the origin rate limit config, or null to disable origin-based limiting
   */
  default RateLimitConfig originRateLimitConfig() {
    // Two tokens per login, so 600/min is 300 logins a minute from one origin. Sized to stay out
    // of the way of a corporate NAT or mobile CGNAT while still bounding a single source, now
    // that the key is aggregated to an IPv6 /64 rather than a bare address — a /64 is one
    // subscriber line, and keying on the full address let a single host mint 2^64 distinct keys.
    // maxEntries is meaningless for the fixed-capacity limiter that backs this, but it is set to
    // a real value rather than 0 so that a consumer wiring this config into the map-backed
    // implementation gets a working limiter instead of one that denies every request.
    return new RateLimitConfig(600, 600.0 / 60, 50_000);
  }


  /**
   * Conservative defaults, sized to bound online guessing rather than to accommodate a busy
   * deployment. Every limit is per credential identifier and per minute; deployments with real
   * traffic figures should implement {@link RateLimitConfigSupplier} directly rather than lean on
   * these. Origin limiting is left disabled, as the interface default.
   */
  class DefaultRateLimitConfigSupplier implements RateLimitConfigSupplier {

    /**
     * Creates a supplier returning the built-in defaults.
     */
    public DefaultRateLimitConfigSupplier() {
    }

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
