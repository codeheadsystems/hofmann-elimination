package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Bounds on the recovery challenge store.
 *
 * <p>The store exists so the verification limiter can key on a value the server chose. Its
 * capacity behaviour therefore decides whether that protection holds under load — and the first
 * version got it backwards, refusing to record at capacity so that every recovery started after a
 * flood fell back to identifier keying. Since {@code recoveryStart} is unauthenticated and its
 * limiter keys on the credential identifier, an attacker varying the identifier is bounded only by
 * the origin limiter, which is off by default. Filling the store was cheap and silently disabled
 * the protection for everyone.
 */
class InMemoryRecoveryChallengeStoreTest {

  private InMemoryRecoveryChallengeStore store;

  @AfterEach
  void tearDown() {
    if (store != null) {
      store.shutdown();
    }
  }

  @Test
  void recordsAndReturnsTheIssuingCredential() {
    store = new InMemoryRecoveryChallengeStore();
    store.store("id-1", "alice");
    assertThat(store.peek("id-1")).hasValue("alice");
  }

  @Test
  void unknownAndNullIdsAreEmpty() {
    store = new InMemoryRecoveryChallengeStore();
    assertThat(store.peek("never-issued")).isEmpty();
    assertThat(store.peek(null)).isEmpty();
  }

  @Test
  void peekIsNonConsuming() {
    // A mistyped code must not restart the recovery.
    store = new InMemoryRecoveryChallengeStore();
    store.store("id-1", "alice");
    assertThat(store.peek("id-1")).hasValue("alice");
    assertThat(store.peek("id-1")).hasValue("alice");
  }

  @Test
  void atCapacityWithNoFlooderPresentTheOldestIsEvicted() {
    // With every holder level — the normal state, since most identifiers hold exactly one — the
    // largest-holder rule reduces to plain oldest-first. The property that matters either way is
    // that a new challenge is still recorded: if they stopped being recorded, everyone's
    // verification would silently fall back to identifier keying.
    store = new InMemoryRecoveryChallengeStore(600, 3, 100);
    store.store("id-1", "alice");
    store.store("id-2", "bob");
    store.store("id-3", "carol");

    store.store("id-4", "dave");

    assertThat(store.peek("id-4")).as("a new challenge must still be recorded").hasValue("dave");
    assertThat(store.peek("id-1")).as("the oldest is what pays").isEmpty();
    assertThat(store.peek("id-3")).hasValue("carol");
  }

  @Test
  void oneIdentifierCannotConsumeTheWholeStore() {
    // The cap still bounds what one identifier holds — it just evicts its own oldest rather than
    // refusing the newest.
    store = new InMemoryRecoveryChallengeStore(600, 100, 2);
    store.store("a-1", "attacker");
    store.store("a-2", "attacker");
    store.store("a-3", "attacker");

    assertThat(store.peek("a-1")).as("the identifier's own oldest pays").isEmpty();
    assertThat(store.peek("a-2")).hasValue("attacker");
    assertThat(store.peek("a-3")).hasValue("attacker");

    store.store("v-1", "victim");
    assertThat(store.peek("v-1")).hasValue("victim");
  }

  /**
   * The targeted lockout, in the form the per-identifier cap accidentally reintroduced.
   *
   * <p>{@code recoveryStart}'s limiter permits a sustained 6/min and the TTL is 600s, so an
   * attacker can hold ~60 outstanding challenges against one identifier — past a cap of 32,
   * reached in five minutes and held. When the cap refused to record, the victim's *real*
   * challenge went unrecorded from then on, their verification fell back to identifier keying,
   * and the attacker drained that separate bucket. Cheaper and more precise than the lockout the
   * feature exists to close.
   */
  @Test
  void anAttackerHoldingAnIdentifierAtItsCapCannotStopTheVictimsChallengeBeingRecorded() {
    store = new InMemoryRecoveryChallengeStore(600, 1000, 4);
    for (int i = 0; i < 20; i++) {
      store.store("flood-" + i, "victim");
    }

    // The victim's real challenge, issued last, must be the one that is recorded.
    store.store("victims-real-challenge", "victim");
    assertThat(store.peek("victims-real-challenge")).hasValue("victim");
  }

  @Test
  void atGlobalCapacityEvictionTakesFromTheLargestHolder() {
    // Not the globally oldest, which is targetable: an attacker filling the store across many
    // identifiers evicts whatever is oldest, including a victim's in-flight challenge. Taking
    // from the largest holder makes flooding self-defeating.
    store = new InMemoryRecoveryChallengeStore(600, 5, 100);
    store.store("v-1", "victim");            // oldest overall, and the victim holds only this
    for (int i = 0; i < 4; i++) {
      store.store("f-" + i, "flooder");
    }

    store.store("f-new", "flooder");

    assertThat(store.peek("v-1"))
        .as("the victim's single in-flight challenge must survive a flood")
        .hasValue("victim");
    assertThat(store.peek("f-0")).as("the flooder's own oldest pays").isEmpty();
  }

  @Test
  void evictingFreesPerIdentifierBudget() {
    // The per-identifier cap has to be a concurrency bound, not a lifetime ceiling. If eviction
    // did not release the count, a user whose entries had been evicted would be permanently
    // refused and would silently lose the protection for good.
    store = new InMemoryRecoveryChallengeStore(600, 2, 2);
    store.store("a-1", "alice");
    store.store("a-2", "alice");        // alice is now at her cap, store is full

    store.store("b-1", "bob");          // alice is the largest holder, so her oldest pays

    assertThat(store.peek("a-1")).isEmpty();
    assertThat(store.peek("b-1")).hasValue("bob");

    // Alice is back under her cap, so a fresh challenge for her is recorded.
    store.store("a-3", "alice");
    assertThat(store.peek("a-3")).hasValue("alice");
  }

  @Test
  void thePerIdentifierCapIsAppliedBeforeGlobalEviction() {
    // Deliberate ordering: one identifier at its own cap must recycle its own entries rather than
    // reach global capacity and evict somebody else's.
    store = new InMemoryRecoveryChallengeStore(600, 10, 2);
    store.store("v-1", "victim");
    store.store("a-1", "attacker");
    store.store("a-2", "attacker");

    store.store("a-3", "attacker");

    assertThat(store.peek("a-3")).hasValue("attacker");
    assertThat(store.peek("a-1")).as("the attacker's own oldest paid").isEmpty();
    assertThat(store.peek("v-1")).as("and nobody else did").hasValue("victim");
  }

  @Test
  void expiredEntriesAreNotReturned() {
    store = new InMemoryRecoveryChallengeStore(0, 100, 100);
    store.store("id-1", "alice");
    assertThat(store.peek("id-1")).isEmpty();
  }

  /**
   * The per-identifier cap must be at least what the recovery limiter permits within one TTL.
   *
   * <p>Under a sustained flood the victim's real challenge is the newest entry for that
   * identifier, so it survives until that many further starts have evicted forward past it. If the
   * cap is below the permitted rate over a TTL, that happens *before* the challenge would have
   * expired anyway — verification falls back to identifier keying and the lockout returns. At 32
   * the window was ~5.3 minutes. Pinning the relationship here so retuning either constant cannot
   * silently reopen it.
   */
  @Test
  void thePerIdentifierCapCoversAFullTtlOfPermittedStarts() {
    double recoveryRefillPerMinute = 6.0;   // RateLimitConfigSupplier.recoveryRateLimitConfig
    double ttlMinutes = InMemoryRecoveryChallengeStore.DEFAULT_TTL_SECONDS / 60.0;

    assertThat(InMemoryRecoveryChallengeStore.DEFAULT_MAX_PER_IDENTIFIER)
        .as("eviction must not shorten a challenge below its natural lifetime")
        .isGreaterThanOrEqualTo((int) Math.ceil(recoveryRefillPerMinute * ttlMinutes));
  }

  @Test
  void underASustainedFloodTheNewestChallengeIsTheOneRetained() {
    // The property the derivation buys: whatever the attacker does, the challenge the user is
    // about to present is the one in the store.
    store = new InMemoryRecoveryChallengeStore(600, 10_000, 8);
    for (int i = 0; i < 200; i++) {
      store.store("flood-" + i, "victim");
      // The most recent start is always recorded, however long the flood runs.
      assertThat(store.peek("flood-" + i)).hasValue("victim");
    }
  }
}
