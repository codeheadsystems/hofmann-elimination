package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * authStart stores a pending session for EVERY request, including the manufactured-KE2 path for
 * unknown credentials — that path exists precisely so an unknown identifier is indistinguishable
 * from a registered one, so it cannot simply be skipped. An attacker who starts handshakes and
 * never finishes them therefore fills this store with entries that are dead but not yet reaped,
 * and every legitimate user gets 503 until the reaper next runs.
 *
 * <p>Refusing when genuinely full is still right; refusing without first dropping entries that
 * are already past their TTL is not.
 */
class PendingSessionCapacityReclaimTest {

  private InMemoryPendingSessionStore store;

  @AfterEach
  void tearDown() {
    if (store != null) {
      store.shutdown();
    }
  }

  private static ServerAuthState state() {
    return new ServerAuthState(new byte[32], new byte[32]);
  }

  /**
   * Uses a long TTL and backdates the entries directly, rather than sleeping past a short one.
   * With a short TTL the background reaper fires during the sleep and empties the store on its
   * own, so the test passes whether or not the on-demand reclaim exists — it was satisfied by
   * pre-existing behaviour and never exercised the new path. Backdating leaves the reaper out of
   * it, so removing evictExpired() from store() fails this test.
   */
  @Test
  void expiredEntriesAreReclaimedSoNewHandshakesAreNotRefused() throws Exception {
    store = new InMemoryPendingSessionStore(3600, 4);

    for (int i = 0; i < 4; i++) {
      store.store("abandoned-" + i, state(), "Y3JlZA==");
    }
    backdateAllEntries(store, 7200);

    assertThatCode(() -> store.store(UUID.randomUUID().toString(), state(), "Y3JlZA=="))
        .as("a legitimate handshake must not be refused because the store is full of entries "
            + "that have already expired")
        .doesNotThrowAnyException();
  }

  /** Rewinds every entry's creation time so it is past its TTL without waiting for it. */
  @SuppressWarnings("unchecked")
  private static void backdateAllEntries(InMemoryPendingSessionStore store, long seconds)
      throws Exception {
    java.lang.reflect.Field sessionsField =
        InMemoryPendingSessionStore.class.getDeclaredField("sessions");
    sessionsField.setAccessible(true);
    java.util.Map<String, Object> sessions =
        (java.util.Map<String, Object>) sessionsField.get(store);
    java.time.Instant past = java.time.Instant.now().minusSeconds(seconds);
    for (java.util.Map.Entry<String, Object> e : sessions.entrySet()) {
      Object entry = e.getValue();
      Object[] parts = new Object[4];
      java.lang.reflect.RecordComponent[] comps =
          entry.getClass().getRecordComponents();
      for (int i = 0; i < comps.length; i++) {
        parts[i] = comps[i].getType() == java.time.Instant.class
            ? past : comps[i].getAccessor().invoke(entry);
      }
      java.lang.reflect.Constructor<?> ctor = entry.getClass().getDeclaredConstructors()[0];
      ctor.setAccessible(true);
      e.setValue(ctor.newInstance(parts));
    }
  }

  @Test
  void genuinelyFullStoreStillRefuses() {
    store = new InMemoryPendingSessionStore(600, 3);

    for (int i = 0; i < 3; i++) {
      store.store("live-" + i, state(), "Y3JlZA==");
    }

    assertThatThrownBy(() -> store.store("one-too-many", state(), "Y3JlZA=="))
        .as("with every entry still live there is nothing to reclaim, so the cap must hold")
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Too many pending sessions");
  }

  @Test
  void reclaimDoesNotDropLiveSessions() throws Exception {
    store = new InMemoryPendingSessionStore(2, 4);

    store.store("keeper", state(), "Y3JlZA==");
    Thread.sleep(100);
    for (int i = 0; i < 3; i++) {
      store.store("filler-" + i, state(), "Y3JlZA==");
    }

    // Nothing has expired yet, so this attempt triggers a reclaim, finds nothing to drop, and
    // correctly refuses. What must NOT happen is the reclaim evicting a live entry to make room.
    assertThatThrownBy(() -> store.store("triggers-reclaim-attempt", state(), "Y3JlZA=="))
        .isInstanceOf(IllegalStateException.class);

    assertThat(store.remove("keeper"))
        .as("a live pending session must survive a failed capacity reclaim — evicting live "
            + "entries to make room would let an attacker cancel other users' handshakes")
        .isPresent();
  }
}
