package com.codeheadsystems.hofmann.server.ratelimit;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

  private static final Logger log = LoggerFactory.getLogger(InMemoryRateLimiter.class);

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
    // Evicting a bucket recreates it full, so eviction must never hand back tokens the refill
    // would not have granted anyway. That holds only while the stale window is at least as long
    // as a full refill takes. Every shipped config satisfies it, but an operator tightening a
    // limit — say recovery to 5/hour — would silently cross the line and turn eviction into a
    // way to reset a throttle. Warn rather than reject, since the limiter is still a net
    // improvement over none and refusing to start would be a harsh response to a tuning choice.
    double secondsToRefill = refillPerSecond > 0
        ? maxTokens / refillPerSecond : Double.POSITIVE_INFINITY;
    if (secondsToRefill > TimeUnit.NANOSECONDS.toSeconds(STALE_THRESHOLD_NANOS)) {
      log.warn("Rate limit config takes {}s to refill {} tokens, longer than the {}s stale "
              + "window. Evicting an idle bucket recreates it full, so an exhausted key that "
              + "idles past the window regains its full budget sooner than the refill rate "
              + "alone would allow. Raise refillPerSecond or lower maxTokens to avoid this.",
          Double.isInfinite(secondsToRefill) ? "infinite" : String.format("%.0f", secondsToRefill),
          maxTokens, TimeUnit.NANOSECONDS.toSeconds(STALE_THRESHOLD_NANOS));
    }
    reaper.scheduleAtFixedRate(this::evictStale, 60, 60, TimeUnit.SECONDS);
  }

  @Override
  public boolean tryConsume(String key) {
    TokenBucket bucket = tryGetOrCreate(key);
    if (bucket == null) {
      // Still at capacity after reclaiming what we could. Denying is the right direction —
      // admitting on overflow would let an attacker bypass the limit by filling the map — but
      // see the note on evictStale() for why reaching this state should be rare.
      log.warn("Rate limiter at capacity ({} entries); denying request for a new key. "
          + "This denies legitimate callers whose bucket is not resident, so treat sustained "
          + "occurrences as an attack on the limiter's key space rather than a tuning problem.",
          maxEntries);
      return false;
    }
    return bucket.tryConsume(maxTokens, refillPerSecond);
  }

  private TokenBucket tryGetOrCreate(final String key) {
    TokenBucket bucket = buckets.computeIfAbsent(key, k ->
        buckets.size() >= maxEntries ? null : new TokenBucket(maxTokens, System.nanoTime()));
    if (bucket != null) {
      return bucket;
    }
    // Reclaim on demand before giving up. The bucket keys are attacker-chosen, so a burst of
    // one-shot identifiers fills the map; without this, every caller whose bucket is not already
    // resident is denied until the 60-second reaper next runs — turning a flood of junk keys into
    // a total outage for legitimate users, which is a worse failure than the memory exhaustion
    // the cap exists to prevent. Entries idle beyond the stale window are fully refilled for every
    // shipped config — see the constructor, which warns if a custom config breaks that.
    evictStale();
    return buckets.computeIfAbsent(key, k ->
        buckets.size() >= maxEntries ? null : new TokenBucket(maxTokens, System.nanoTime()));
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }

  // Package-private test helpers
  int bucketCount() {
    return buckets.size();
  }

  void runEvictionNow() {
    evictStale();
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
