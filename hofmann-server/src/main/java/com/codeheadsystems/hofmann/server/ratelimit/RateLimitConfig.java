package com.codeheadsystems.hofmann.server.ratelimit;

/**
 * Configuration for a token-bucket rate limiter.
 *
 * @param maxTokens       maximum burst size (tokens available at any instant)
 * @param refillPerSecond rate at which tokens are replenished
 * @param maxEntries      maximum number of tracked keys (prevents OOM from key enumeration)
 */
public record RateLimitConfig(int maxTokens, double refillPerSecond, int maxEntries) {

  /**
   * Default configuration for OPAQUE authentication endpoints.
   * 10 burst, ~10 per minute per credential.
   *
   * @return the rate limit config
   */
  public static RateLimitConfig authDefault() {
    return new RateLimitConfig(10, 10.0 / 60, 50_000);
  }

  /**
   * Default configuration for OPAQUE registration endpoints.
   * 5 burst, ~5 per minute per credential.
   *
   * @return the rate limit config
   */
  public static RateLimitConfig registrationDefault() {
    return new RateLimitConfig(5, 5.0 / 60, 50_000);
  }

  /**
   * Default configuration for the standalone OPRF endpoint.
   * 30 burst, ~30 per minute per IP.
   *
   * @return the rate limit config
   */
  public static RateLimitConfig oprfDefault() {
    return new RateLimitConfig(30, 30.0 / 60, 50_000);
  }
}
