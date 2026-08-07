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
  void atCapacityTheOldestIsEvictedAndNewChallengesAreStillRecorded() {
    // The property that failed before: a flood must cost the oldest outstanding challenges, not
    // every future one. If new challenges stop being recorded, everyone's verification silently
    // falls back to identifier keying — the lockout, restored globally, by log line only.
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
    // Bounds the flood at its source, so a single identifier being hammered cannot displace
    // anybody else's challenge.
    store = new InMemoryRecoveryChallengeStore(600, 100, 2);
    store.store("a-1", "attacker");
    store.store("a-2", "attacker");
    store.store("a-3", "attacker");

    assertThat(store.peek("a-3")).as("beyond the per-identifier cap").isEmpty();
    assertThat(store.peek("a-1")).hasValue("attacker");

    // And another identifier is unaffected.
    store.store("v-1", "victim");
    assertThat(store.peek("v-1")).hasValue("victim");
  }

  @Test
  void evictingFreesPerIdentifierBudget() {
    // The per-identifier cap has to be a concurrency bound, not a lifetime ceiling. If eviction
    // did not release the count, a user whose entries had been evicted would be permanently
    // refused and would silently lose the protection for good.
    store = new InMemoryRecoveryChallengeStore(600, 2, 2);
    store.store("a-1", "alice");
    store.store("a-2", "alice");        // alice is now at her cap, store is full

    store.store("b-1", "bob");          // evicts a-1, releasing one of alice's slots

    assertThat(store.peek("a-1")).isEmpty();
    assertThat(store.peek("b-1")).hasValue("bob");

    // Alice is back under her cap, so a fresh challenge for her is recorded rather than refused.
    store.store("a-3", "alice");
    assertThat(store.peek("a-3")).hasValue("alice");
  }

  @Test
  void thePerIdentifierCapIsCheckedBeforeGlobalEviction() {
    // Deliberate ordering: one identifier flooding its own cap must not be able to evict other
    // identifiers' challenges on the way to being refused.
    store = new InMemoryRecoveryChallengeStore(600, 10, 2);
    store.store("v-1", "victim");
    store.store("a-1", "attacker");
    store.store("a-2", "attacker");

    store.store("a-3", "attacker");

    assertThat(store.peek("a-3")).as("refused by the per-identifier cap").isEmpty();
    assertThat(store.peek("v-1")).as("and nobody else paid for it").hasValue("victim");
  }

  @Test
  void expiredEntriesAreNotReturned() {
    store = new InMemoryRecoveryChallengeStore(0, 100, 100);
    store.store("id-1", "alice");
    assertThat(store.peek("id-1")).isEmpty();
  }
}
