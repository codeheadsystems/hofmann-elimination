package com.codeheadsystems.hofmann.server.ratelimit;

/**
 * Rate limiter interface for controlling request throughput.
 * <p>
 * The default implementation is {@link InMemoryRateLimiter}, which uses an in-memory
 * token bucket per key. For multi-instance deployments, provide a custom implementation
 * backed by Redis, Hazelcast, or another distributed store.
 * <p>
 * In Spring Boot, override the default bean:
 * <pre>{@code
 *   @Bean
 *   public RateLimiter authRateLimiter() {
 *     return new MyRedisRateLimiter(redisClient, RateLimitConfig.authDefault());
 *   }
 * }**</pre>
 * <p>
 * In Dropwizard, pass to the bundle:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore, null)
 *       .withAuthRateLimiter(myRedisLimiter));
 * }**</pre>
 */
public interface RateLimiter {

  /**
   * Attempts to consume one token for the given key.
   *
   * @param key the rate limit key (e.g., credential identifier, client IP)
   * @return {@code true} if the request is allowed, {@code false} if rate limit exceeded
   */
  boolean tryConsume(String key);

  /**
   * Releases any resources held by this rate limiter (e.g., background threads).
   * The default implementation is a no-op.
   */
  default void shutdown() {
  }
}
