package com.codeheadsystems.hofmann.server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The map-backed limiter allocates a bucket per distinct key and denies once at capacity, so a
 * flood of attacker-chosen keys locks out every caller whose bucket is not resident. Reclaiming
 * stale entries helps only against an attacker who stops; one that keeps 50,000 keys warm inside
 * the stale window sustains the outage indefinitely.
 *
 * <p>This implementation has no capacity condition to reach.
 */
class FixedCapacityRateLimiterTest {

  private static RateLimitConfig config(int tokens) {
    return new RateLimitConfig(tokens, tokens / 60.0, 0);
  }

  /**
   * The actual reported attack: ~50,000 distinct one-shot keys, which is enough to fill the
   * map-backed limiter and deny every caller whose bucket is not resident. Here those keys spread
   * across the default slot count, so most slots are never touched and the rest keep almost their
   * full budget.
   *
   * <p><strong>What this does not claim.</strong> Bounding memory does not bound request volume:
   * an attacker sending enough traffic to drain every slot still denies service, exactly as they
   * would by saturating any per-key limit. What is gone is the disproportionate case — a low-rate
   * flood of distinct keys causing a total outage purely by exhausting capacity, at a cost far
   * below what saturating the buckets would take.
   */
  @Test
  void aFloodOfDistinctKeysDoesNotLockOutANewCaller() {
    FixedCapacityRateLimiter limiter = new FixedCapacityRateLimiter(config(10));

    for (int i = 0; i < 50_000; i++) {
      limiter.tryConsume(UUID.randomUUID().toString());
    }

    int admitted = 0;
    for (int i = 0; i < 200; i++) {
      if (limiter.tryConsume("legitimate-" + i)) {
        admitted++;
      }
    }
    assertThat(admitted)
        .as("after the reported 50k-key flood a legitimate caller must still get through; a "
            + "map-backed limiter at capacity denies all of these")
        .isGreaterThan(190);
  }

  /** Sustaining the flood must not change that — the map-backed limiter's outage was indefinite. */
  @Test
  void sustainingTheFloodDoesNotLockOutNewCallers() {
    FixedCapacityRateLimiter limiter = new FixedCapacityRateLimiter(config(10));

    for (int round = 0; round < 4; round++) {
      for (int i = 0; i < 50_000; i++) {
        limiter.tryConsume(UUID.randomUUID().toString());
      }
      assertThat(limiter.tryConsume("legitimate-round-" + round))
          .as("round %d: the outage must not accumulate", round)
          .isTrue();
    }
  }

  @Test
  void memoryIsFixedRegardlessOfKeyCount() {
    FixedCapacityRateLimiter limiter = new FixedCapacityRateLimiter(config(10), 256);
    int before = limiter.slotCount();

    for (int i = 0; i < 100_000; i++) {
      limiter.tryConsume(UUID.randomUUID().toString());
    }

    assertThat(limiter.slotCount())
        .as("the structure must not grow with the number of distinct keys")
        .isEqualTo(before);
  }

  @Test
  void aSingleKeyIsStillThrottled() {
    FixedCapacityRateLimiter limiter = new FixedCapacityRateLimiter(config(5), 1024);

    int admitted = 0;
    for (int i = 0; i < 20; i++) {
      if (limiter.tryConsume("one-key")) {
        admitted++;
      }
    }
    assertThat(admitted)
        .as("bounding memory must not stop the limiter limiting")
        .isEqualTo(5);
  }

  @Test
  void slotCountIsRoundedToAPowerOfTwo() {
    assertThat(new FixedCapacityRateLimiter(config(5), 1000).slotCount()).isEqualTo(1024);
    assertThat(new FixedCapacityRateLimiter(config(5), 1024).slotCount()).isEqualTo(1024);
  }

  /**
   * The property the whole design rests on, and the one an earlier version got wrong.
   *
   * <p>That version computed {@code key.hashCode() ^ seed}. Because {@code String.hashCode}
   * collapses to 32 bits first, two keys with equal hashCode shared a slot under EVERY seed — and
   * such pairs are constructible offline with no knowledge of it, since the function is linear in
   * the characters. The seed randomised the slot number while leaving the collision relation
   * fully predictable, so an attacker who could choose their own key could compute one sharing a
   * chosen victim's slot and drain that victim's budget at the refill rate.
   *
   * <p>"Aa" and "BB" are the canonical equal-hashCode pair. They must now land together only by
   * chance, at roughly the collision rate of any unrelated pair.
   */
  @Test
  void keysWithEqualStringHashCodeDoNotShareASlot() {
    assertThat("Aa".hashCode())
        .as("premise: these are the classic equal-hashCode pair")
        .isEqualTo("BB".hashCode());

    int collisions = 0;
    int trials = 200;
    for (int i = 0; i < trials; i++) {
      FixedCapacityRateLimiter limiter = new FixedCapacityRateLimiter(config(1), 1024);
      limiter.tryConsume("Aa");
      if (!limiter.tryConsume("BB")) {
        collisions++;
      }
    }
    // With the seed applied before the collapse this is ~1/1024 per trial; with the old scheme it
    // was 200/200. Anything approaching the trial count means the seed is not reaching the key.
    assertThat(collisions)
        .as("equal String.hashCode must not imply an equal slot; saw %d/%d collisions",
            collisions, trials)
        .isLessThan(trials / 10);
  }

  /**
   * Same property from the other direction: an attacker who can pick their own key must not be
   * able to reproduce a collision across processes.
   */
  @Test
  void collisionLayoutIsNotReproducibleAcrossInstances() {
    int reproduced = 0;
    int trials = 200;
    for (int i = 0; i < trials; i++) {
      FixedCapacityRateLimiter a = new FixedCapacityRateLimiter(config(1), 64);
      FixedCapacityRateLimiter b = new FixedCapacityRateLimiter(config(1), 64);
      a.tryConsume("victim");
      b.tryConsume("victim");
      boolean collidesInA = !a.tryConsume("attacker-chosen");
      boolean collidesInB = !b.tryConsume("attacker-chosen");
      if (collidesInA && collidesInB) {
        reproduced++;
      }
    }
    // Independent 1/64 events, so ~1/4096 of trials. A shared layout would give ~1/64.
    assertThat(reproduced)
        .as("a collision must not carry across independently seeded processes; saw %d/%d",
            reproduced, trials)
        .isLessThan(trials / 20);
  }

  @Test
  void nonPositiveSlotCountIsRejected() {
    for (int bad : new int[]{0, -1, Integer.MIN_VALUE}) {
      org.assertj.core.api.Assertions
          .assertThatThrownBy(() -> new FixedCapacityRateLimiter(config(5), bad))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  /** {@code highestOneBit(x) * 2} overflows to a negative array size above 2^30. */
  @Test
  void absurdSlotCountsDoNotOverflow() {
    for (int big : new int[]{1 << 30, (1 << 30) + 1, Integer.MAX_VALUE}) {
      assertThat(new FixedCapacityRateLimiter(config(5), big).slotCount())
          .as("slot count %d must be capped rather than overflowing", big)
          .isPositive();
    }
  }

  @Test
  void nullKeyDoesNotThrow() {
    assertThat(new FixedCapacityRateLimiter(config(5), 64).tryConsume(null)).isTrue();
  }
}
