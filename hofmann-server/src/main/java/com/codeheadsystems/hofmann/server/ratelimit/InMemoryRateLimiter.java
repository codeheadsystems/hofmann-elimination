package com.codeheadsystems.hofmann.server.ratelimit;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory token-bucket rate limiter.
 * <p>
 * Each key (credential identifier, client IP, etc.) gets its own token bucket.
 * Tokens are replenished lazily on each {@link #tryConsume} call. A background
 * reaper thread removes stale entries to bound memory usage.
 * <p>
 * This implementation is suitable for single-JVM deployments. For multi-instance
 * deployments, implement {@link RateLimiter} with a distributed backend (e.g., Redis).
 */
public class InMemoryRateLimiter implements RateLimiter {

  private static final long STALE_THRESHOLD_NANOS = TimeUnit.MINUTES.toNanos(5);

  private final int maxTokens;
  private final double refillPerSecond;
  private final int maxEntries;
  private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

  private final ScheduledExecutorService reaper =
      Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "rate-limiter-reaper");
        t.setDaemon(true);
        return t;
      });

  /**
   * Instantiates a new In memory rate limiter.
   *
   * @param config the rate limit configuration
   */
  public InMemoryRateLimiter(RateLimitConfig config) {
    this.maxTokens = config.maxTokens();
    this.refillPerSecond = config.refillPerSecond();
    this.maxEntries = config.maxEntries();
    reaper.scheduleAtFixedRate(this::evictStale, 60, 60, TimeUnit.SECONDS);
  }

  @Override
  public boolean tryConsume(String key) {
    TokenBucket bucket = buckets.computeIfAbsent(key, k -> {
      if (buckets.size() >= maxEntries) {
        return null;
      }
      return new TokenBucket(maxTokens, System.nanoTime());
    });
    if (bucket == null) {
      // At capacity — deny by default to prevent OOM-based bypass
      return false;
    }
    return bucket.tryConsume(maxTokens, refillPerSecond);
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }

  private void evictStale() {
    long now = System.nanoTime();
    buckets.entrySet().removeIf(e -> (now - e.getValue().lastAccessNanos.get()) > STALE_THRESHOLD_NANOS);
  }

  private static class TokenBucket {
    private final AtomicLong lastAccessNanos;
    private double tokens;
    private long lastRefillNanos;

    TokenBucket(int maxTokens, long nowNanos) {
      this.tokens = maxTokens;
      this.lastRefillNanos = nowNanos;
      this.lastAccessNanos = new AtomicLong(nowNanos);
    }

    synchronized boolean tryConsume(int maxTokens, double refillPerSecond) {
      long now = System.nanoTime();
      lastAccessNanos.set(now);

      double elapsed = (now - lastRefillNanos) / 1_000_000_000.0;
      tokens = Math.min(maxTokens, tokens + elapsed * refillPerSecond);
      lastRefillNanos = now;

      if (tokens >= 1.0) {
        tokens -= 1.0;
        return true;
      }
      return false;
    }
  }
}
