package com.codeheadsystems.hofmann.server.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The limiter's keys are attacker-chosen — a credential identifier taken straight from an
 * unauthenticated request body. Filling the map with one-shot junk keys therefore used to deny
 * every caller whose bucket was not already resident, for up to a full reaper period. That turns
 * a cheap flood into a total outage for legitimate users, which is a worse outcome than the
 * memory exhaustion the cap exists to prevent.
 *
 * <p>Denying on genuine overflow is still correct — admitting would let an attacker bypass the
 * limit entirely by filling the map — so the fix is to reclaim stale entries on demand before
 * concluding the map is full.
 */
class RateLimiterCapacityReclaimTest {

  private InMemoryRateLimiter limiter;

  @AfterEach
  void tearDown() {
    if (limiter != null) {
      limiter.shutdown();
    }
  }

  /** Entries idle past the stale window are fully refilled and carry no state worth keeping. */
  @Test
  void staleEntriesAreReclaimedSoNewKeysAreNotLockedOut() throws Exception {
    limiter = new InMemoryRateLimiter(new RateLimitConfig(5, 5.0, 8));

    for (int i = 0; i < 8; i++) {
      assertThat(limiter.tryConsume("flood-" + i)).isTrue();
    }
    assertThat(limiter.bucketCount()).isEqualTo(8);

    // Age every entry past the stale threshold, exactly as an abandoned flood would.
    ageAllBucketsPastStaleThreshold(limiter);

    assertThat(limiter.tryConsume("legitimate-user"))
        .as("a caller arriving after a flood of one-shot keys must not be denied because the "
            + "map is full of entries that are already stale")
        .isTrue();
  }

  /** A genuinely full map of ACTIVE keys must still deny — otherwise the cap is bypassable. */
  @Test
  void activeEntriesAreNotReclaimedAndOverflowStillDenies() {
    limiter = new InMemoryRateLimiter(new RateLimitConfig(5, 5.0, 4));

    for (int i = 0; i < 4; i++) {
      assertThat(limiter.tryConsume("active-" + i)).isTrue();
    }

    assertThat(limiter.tryConsume("one-too-many"))
        .as("with every entry freshly active there is nothing to reclaim, so overflow must "
            + "still deny rather than admit — admitting would bypass the limit")
        .isFalse();
    assertThat(limiter.bucketCount()).isEqualTo(4);
  }

  /** Reclaiming must not hand back tokens to a key that is still being throttled. */
  @Test
  void reclaimDoesNotResetAnActiveKeysBudget() {
    limiter = new InMemoryRateLimiter(new RateLimitConfig(2, 0.0001, 4));

    assertThat(limiter.tryConsume("victim")).isTrue();
    assertThat(limiter.tryConsume("victim")).isTrue();
    assertThat(limiter.tryConsume("victim")).isFalse();

    for (int i = 0; i < 3; i++) {
      limiter.tryConsume("other-" + i);
    }
    limiter.tryConsume("overflow-trigger");

    assertThat(limiter.tryConsume("victim"))
        .as("an exhausted key must stay exhausted across a reclaim, or flooding the map "
            + "would become a way to reset someone's rate limit")
        .isFalse();
  }

  @Test
  void floodOfDistinctKeysDoesNotPermanentlyDenyNewCallers() throws Exception {
    limiter = new InMemoryRateLimiter(new RateLimitConfig(5, 5.0, 64));

    for (int round = 0; round < 3; round++) {
      for (int i = 0; i < 64; i++) {
        limiter.tryConsume(UUID.randomUUID().toString());
      }
      ageAllBucketsPastStaleThreshold(limiter);
      assertThat(limiter.tryConsume("legitimate-round-" + round))
          .as("round %d: a legitimate caller must get through after each flood", round)
          .isTrue();
    }
  }

  /**
   * Rewinds every bucket's last-refill timestamp past the stale threshold. Reaching into the
   * internals beats sleeping for five minutes, and the alternative — a configurable threshold —
   * would add production surface that exists only for tests.
   */
  private static void ageAllBucketsPastStaleThreshold(InMemoryRateLimiter limiter)
      throws Exception {
    java.lang.reflect.Field bucketsField =
        InMemoryRateLimiter.class.getDeclaredField("buckets");
    bucketsField.setAccessible(true);
    @SuppressWarnings("unchecked")
    java.util.Map<String, Object> buckets =
        (java.util.Map<String, Object>) bucketsField.get(limiter);
    long ancient = System.nanoTime() - java.util.concurrent.TimeUnit.MINUTES.toNanos(30);
    for (Object bucket : buckets.values()) {
      for (java.lang.reflect.Field f : bucket.getClass().getDeclaredFields()) {
        if (f.getType() == java.util.concurrent.atomic.AtomicLong.class) {
          f.setAccessible(true);
          ((java.util.concurrent.atomic.AtomicLong) f.get(bucket)).set(ancient);
        }
      }
    }
  }
}
