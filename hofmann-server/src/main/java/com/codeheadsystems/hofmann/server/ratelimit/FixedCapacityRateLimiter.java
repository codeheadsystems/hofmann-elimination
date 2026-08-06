package com.codeheadsystems.hofmann.server.ratelimit;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token-bucket rate limiter over a fixed set of pre-allocated buckets.
 *
 * <p>Exists because a map keyed on attacker-chosen values cannot be made safe by bounding it.
 * {@link InMemoryRateLimiter} allocates a bucket per distinct key and denies once it reaches
 * capacity, so a flood of one-shot keys locks out every caller whose bucket is not resident —
 * turning a cheap flood into a total outage. Reclaiming stale entries on demand helps only
 * against an attacker who stops: one that touches each key inside the stale window keeps every
 * entry alive, and the outage holds indefinitely.
 *
 * <p>Here a key hashes into an existing slot rather than allocating a new one. Memory is fixed at
 * construction and the structure cannot be filled, so there is no capacity condition and no
 * capacity-driven denial. The failure the other implementation has is not mitigated, it is absent.
 *
 * <p><strong>The trade is precision.</strong> Distinct keys can share a slot and therefore share a
 * budget. With {@code slots} buckets the chance a given key collides with a specific victim is
 * {@code 1/slots}, so at the default 65,536 an attacker cannot meaningfully target one account by
 * flooding — and, critically, the hash is seeded from a per-process random value, so which keys
 * collide cannot be computed offline or reproduced across restarts. Collisions cost accuracy, not
 * safety; exhausting a map costs availability. This trades the second for the first.
 *
 * <p><strong>What this does not do.</strong> Bounding memory does not bound request volume. An
 * attacker sending enough traffic to drain every slot still denies service, exactly as they would
 * by saturating any per-key limit. What is removed is the disproportionate case: a low-rate flood
 * of distinct keys causing a total outage purely by exhausting capacity, at a fraction of the cost
 * of actually saturating the buckets.
 *
 * <p>Suitable wherever the key space is attacker-controlled — client addresses, credential
 * identifiers. For a small, trusted key space {@link InMemoryRateLimiter} gives exact per-key
 * accounting and remains the better choice.
 */
public class FixedCapacityRateLimiter implements RateLimiter {

  private static final Logger log = LoggerFactory.getLogger(FixedCapacityRateLimiter.class);

  /** Bucket count. A power of two so slot selection is a mask rather than a modulo. */
  public static final int DEFAULT_SLOTS = 65_536;

  private final int mask;
  private final long seed;
  private final int maxTokens;
  private final double refillPerSecond;
  private final TokenBucket[] slots;

  /**
   * Creates a limiter with the default slot count.
   *
   * @param config the token-bucket configuration; {@code maxEntries} is ignored, since capacity
   *               is fixed and there is nothing to bound
   */
  public FixedCapacityRateLimiter(final RateLimitConfig config) {
    this(config, DEFAULT_SLOTS);
  }

  /**
   * Creates a limiter with an explicit slot count.
   *
   * @param config the token-bucket configuration
   * @param requestedSlots number of buckets; rounded up to a power of two
   */
  public FixedCapacityRateLimiter(final RateLimitConfig config, final int requestedSlots) {
    int size = Integer.highestOneBit(Math.max(2, requestedSlots - 1)) * 2;
    this.mask = size - 1;
    this.maxTokens = config.maxTokens();
    this.refillPerSecond = config.refillPerSecond();
    // Per-process seed. Without it an attacker could compute which keys share a slot with a
    // chosen victim and drain that slot deliberately, which would turn a precision trade-off
    // into a targeting primitive.
    this.seed = new SecureRandom().nextLong();
    this.slots = new TokenBucket[size];
    long now = System.nanoTime();
    for (int i = 0; i < size; i++) {
      slots[i] = new TokenBucket(maxTokens, now);
    }
    log.debug("FixedCapacityRateLimiter with {} slots, {} tokens, {}/s refill",
        size, maxTokens, refillPerSecond);
  }

  @Override
  public boolean tryConsume(final String key) {
    return slots[slotFor(key)].tryConsume(maxTokens, refillPerSecond);
  }

  private int slotFor(final String key) {
    // A seeded 64-bit mix of the key's hash. String.hashCode alone is trivially collidable by
    // construction, which would let an attacker land on a chosen slot; mixing with a secret seed
    // makes the mapping unpredictable without needing a full cryptographic hash on a path that
    // runs per request.
    long h = (key == null ? 0 : key.hashCode()) ^ seed;
    h *= 0xff51afd7ed558ccdL;
    h ^= h >>> 33;
    h *= 0xc4ceb9fe1a85ec53L;
    h ^= h >>> 33;
    return (int) (h & mask);
  }

  @Override
  public void shutdown() {
    // Nothing to release: no background reaper, and no entries to expire.
  }

  /** Number of buckets. Package-private for tests. */
  int slotCount() {
    return slots.length;
  }

  /** Token bucket with lazy refill, identical in behaviour to the map-backed limiter's. */
  private static final class TokenBucket {
    private final AtomicLong lastRefillNanos;
    private double tokens;

    TokenBucket(final int initialTokens, final long nowNanos) {
      this.tokens = initialTokens;
      this.lastRefillNanos = new AtomicLong(nowNanos);
    }

    synchronized boolean tryConsume(final int maxTokens, final double refillPerSecond) {
      long now = System.nanoTime();
      long previous = lastRefillNanos.getAndSet(now);
      double elapsedSeconds = (now - previous) / (double) TimeUnit.SECONDS.toNanos(1);
      tokens = Math.min(maxTokens, tokens + elapsedSeconds * refillPerSecond);
      if (tokens >= 1.0) {
        tokens -= 1.0;
        return true;
      }
      return false;
    }
  }
}
