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
 * flooding — and the per-process seed is folded through the key's characters, so which keys
 * collide cannot be solved for offline or reproduced across restarts. (Seeding only the final
 * 32-bit hash would not achieve this: equal {@code String.hashCode} values would collide under
 * every seed, and those collisions are constructible with no knowledge of it.) Collisions cost accuracy, not
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

  private static final long FNV_OFFSET_BASIS = 0xcbf29ce484222325L;
  private static final long FNV_PRIME = 0x100000001b3L;

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
    if (requestedSlots < 1) {
      throw new IllegalArgumentException("slots must be positive, got " + requestedSlots);
    }
    // Cap before doubling: highestOneBit(x) * 2 overflows to a negative array size above 2^30.
    int bounded = Math.min(requestedSlots, 1 << 20);
    int size = Integer.highestOneBit(Math.max(2, bounded - 1)) * 2;
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
    if (key == null) {
      return (int) (mix(seed) & mask);
    }
    // The seed must enter BEFORE the key is collapsed to a fixed width, and must be combined with
    // the key's CHARACTERS rather than with String.hashCode.
    //
    // An earlier version computed `key.hashCode() ^ seed`. Because hashCode collapses to 32 bits
    // first, any two keys with equal hashCode landed in the same slot for every possible seed —
    // and String.hashCode collisions are constructible offline with no knowledge of the seed,
    // since the function is linear in the characters. That let an attacker who could choose their
    // own key (any IPv6 prefix they route, or any credential identifier) compute one colliding
    // with a chosen victim and drain the victim's budget at the refill rate. The seed made the
    // slot NUMBER unpredictable while leaving the collision RELATION fully predictable, which is
    // the property that mattered.
    //
    // Folding the seed through a 64-bit FNV-1a over the characters removes that: two keys collide
    // only if they collide after mixing under this process's seed, which cannot be solved for
    // without knowing it. Not a cryptographic MAC — an attacker who learns the seed can still
    // grind collisions — but it costs a few nanoseconds per request and removes the offline
    // attack, which is the one that matters here.
    long h = FNV_OFFSET_BASIS ^ seed;
    for (int i = 0; i < key.length(); i++) {
      h ^= key.charAt(i);
      h *= FNV_PRIME;
    }
    return (int) (mix(h) & mask);
  }

  /** Final avalanche so low-order bits, which the mask selects, depend on the whole hash. */
  private static long mix(final long value) {
    long h = value;
    h ^= h >>> 33;
    h *= 0xff51afd7ed558ccdL;
    h ^= h >>> 33;
    h *= 0xc4ceb9fe1a85ec53L;
    h ^= h >>> 33;
    return h;
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
