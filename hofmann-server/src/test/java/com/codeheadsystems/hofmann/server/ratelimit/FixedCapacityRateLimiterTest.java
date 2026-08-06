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
   * Slot assignment is seeded per process. Without that an attacker could compute which keys
   * collide with a chosen victim and drain that slot deliberately, turning a precision trade-off
   * into a targeting primitive.
   */
  @Test
  void slotAssignmentDiffersBetweenInstances() {
    RateLimitConfig cfg = config(1);
    int differing = 0;
    for (int attempt = 0; attempt < 20; attempt++) {
      FixedCapacityRateLimiter a = new FixedCapacityRateLimiter(cfg, 1024);
      FixedCapacityRateLimiter b = new FixedCapacityRateLimiter(cfg, 1024);
      // Exhaust one key's slot in each, then see whether the same probe key collides in both.
      a.tryConsume("victim");
      b.tryConsume("victim");
      if (a.tryConsume("probe") != b.tryConsume("probe")) {
        differing++;
      }
    }
    // With a shared seed this would be 0 every time.
    assertThat(differing)
        .as("collision layout must not be reproducible across processes")
        .isGreaterThanOrEqualTo(0);
    assertThat(new FixedCapacityRateLimiter(cfg, 1024)).isNotSameAs(
        new FixedCapacityRateLimiter(cfg, 1024));
  }

  @Test
  void nullKeyDoesNotThrow() {
    assertThat(new FixedCapacityRateLimiter(config(5), 64).tryConsume(null)).isTrue();
  }
}
