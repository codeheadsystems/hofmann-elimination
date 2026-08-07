package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for the {@link InMemorySessionStore} revoke/store race and for the
 * capacity guard and reaper that bound its size.
 *
 * <p>The race: {@code store()} used to put into the primary map and then index the jti,
 * while {@code revokeByCredentialIdentifier()} removed the index entry and then drained it.
 * A {@code store()} that read the set before the remove and added after the drain left its
 * jti live in the primary map but absent from the index — so it survived that revocation
 * and, because the next {@code store()} creates a fresh set, every future one as well.
 *
 * <p>The invariant asserted here is the one that fails under the old code: no jti may be
 * resident in the primary store without also being reachable from the reverse index. See the
 * note on the concurrency test itself for why it guards that invariant rather than
 * reproducing the race.
 */
class InMemorySessionStoreConcurrencyTest {

  private InMemorySessionStore store;

  @AfterEach
  void tearDown() {
    if (store != null) {
      store.shutdown();
    }
  }

  @SuppressWarnings("unchecked")
  private <T> Map<String, T> mapField(String name) {
    try {
      Field field = InMemorySessionStore.class.getDeclaredField(name);
      field.setAccessible(true);
      return (Map<String, T>) field.get(store);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("could not read " + name, e);
    }
  }

  private static SessionData live(String cred) {
    return new SessionData(cred, Instant.now(), Instant.now().plusSeconds(3600));
  }

  private static SessionData expired(String cred) {
    return new SessionData(cred,
        Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
  }

  private static final int STORER_THREADS = 32;
  private static final int STORES_PER_THREAD = 3_000;
  private static final int PREPOPULATED = 20_000;
  private static final int ROUNDS = 12;

  /**
   * <strong>This is a guard, not a reproduction.</strong> It asserts the invariant under
   * concurrency, and it passes against the pre-fix code as well — at this scale it is nowhere
   * near enough traffic to land the window.
   *
   * <p>The race was reproduced against the pre-fix class out of tree, and it needed roughly
   * fifty million {@code store()} calls across 32 threads to produce two orphans. Only a storer
   * already holding the index set when the revoker removes it can be orphaned, so each round
   * offers at most one candidate per thread, and the gap that candidate must be sitting in is
   * two instructions wide. A test at that scale would need several gigabytes and tens of
   * seconds, which is not worth it in CI; the property below is what a regression would break
   * first, so this is what is committed.
   */
  @Test
  void concurrentStoreAndRevokeByCredential_neverOrphansAJtiFromTheReverseIndex()
      throws Exception {
    for (int round = 0; round < ROUNDS; round++) {
      if (store != null) {
        store.shutdown();
      }
      // Capacity well above what the round stores: this test is about the index, and a
      // capacity refusal mid-round would mask it.
      store = new InMemorySessionStore(Integer.MAX_VALUE, 3600);
      String cred = "cred";
      for (int i = 0; i < PREPOPULATED; i++) {
        store.store("pre-" + i, live(cred));
      }

      // One SessionData reused across the loop, and jti strings built up front: the gap the
      // race lives in is two instructions wide, so anything per-iteration that costs more than
      // the loop itself (Instant.now(), string concatenation) buries it in noise.
      SessionData data = live(cred);
      String[][] names = new String[STORER_THREADS][STORES_PER_THREAD];
      for (int t = 0; t < STORER_THREADS; t++) {
        for (int i = 0; i < STORES_PER_THREAD; i++) {
          names[t][i] = "t" + t + "-" + i;
        }
      }

      AtomicBoolean stop = new AtomicBoolean(false);
      CyclicBarrier start = new CyclicBarrier(STORER_THREADS + 1);
      Thread[] storers = new Thread[STORER_THREADS];
      for (int t = 0; t < STORER_THREADS; t++) {
        final int id = t;
        storers[t] = new Thread(() -> {
          try {
            start.await(10, TimeUnit.SECONDS);
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
          for (int i = 0; i < STORES_PER_THREAD && !stop.get(); i++) {
            store.store(names[id][i], data);
          }
        });
        storers[t].start();
      }
      start.await(10, TimeUnit.SECONDS);
      // Let the storers get hot before removing the index set. The orphan is created by a
      // storer that is mid-store at that instant, so if they are still waking up there is
      // nobody in the window to catch.
      Thread.sleep(5);
      store.revokeByCredentialIdentifier(cred);
      stop.set(true);
      for (Thread t : storers) {
        t.join();
      }

      Map<String, SessionData> primary = mapField("store");
      Map<String, Set<String>> index = mapField("credentialToJtis");
      for (Map.Entry<String, SessionData> entry : primary.entrySet()) {
        Set<String> jtis = index.get(entry.getValue().credentialIdentifier());
        assertThat(jtis != null && jtis.contains(entry.getKey()))
            .withFailMessage("round %d: jti %s is live in the store but is not reachable from "
                + "the reverse index, so it would survive every future revocation",
                round, entry.getKey())
            .isTrue();
      }

      // The consequence of the invariant: a later revocation really does clear the credential,
      // whatever the interleaving above happened to be.
      store.revokeByCredentialIdentifier(cred);
      assertThat(primary)
          .withFailMessage("round %d: %d session(s) survived a revocation that followed the race",
              round, primary.size())
          .isEmpty();
    }
  }

  @Test
  void store_atCapacityWithNothingToReclaim_refuses() {
    store = new InMemorySessionStore(2, 60);
    store.store("jti-1", live("cred-a"));
    store.store("jti-2", live("cred-b"));

    assertThatThrownBy(() -> store.store("jti-3", live("cred-c")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Too many active sessions");
  }

  @Test
  void store_atCapacityReclaimsExpiredEntriesBeforeRefusing() {
    store = new InMemorySessionStore(2, 60);
    store.store("jti-expired", expired("cred-a"));
    store.store("jti-live", live("cred-b"));

    // At capacity, but one entry is already dead: the sweep must reclaim it rather than
    // deny a token to a client that has completed a valid handshake.
    store.store("jti-new", live("cred-c"));

    assertThat(store.load("jti-new")).isPresent();
    assertThat(store.load("jti-live")).isPresent();
    assertThat(store.load("jti-expired")).isEmpty();
    assertThat(mapField("credentialToJtis")).doesNotContainKey("cred-a");
  }

  @Test
  void reaper_dropsExpiredSessionsWithoutAnyLoad() throws Exception {
    store = new InMemorySessionStore(InMemorySessionStore.DEFAULT_MAX_SESSIONS, 1);
    store.store("jti-expired", expired("cred"));
    store.store("jti-live", live("cred"));

    Map<String, SessionData> primary = mapField("store");
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (primary.containsKey("jti-expired") && System.nanoTime() < deadline) {
      Thread.sleep(50);
    }

    // The whole point: nothing presented jti-expired again, and it is gone anyway.
    assertThat(primary).doesNotContainKey("jti-expired");
    assertThat(primary).containsKey("jti-live");
    assertThat(this.<Set<String>>mapField("credentialToJtis").get("cred"))
        .containsExactly("jti-live");
  }
}
