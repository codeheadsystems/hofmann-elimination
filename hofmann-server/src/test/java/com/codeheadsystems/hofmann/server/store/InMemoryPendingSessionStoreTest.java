package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link InMemoryPendingSessionStore}.
 *
 * <p>Covers consume-once semantics, TTL expiry, the capacity guard, and the issue-7 regression:
 * a 1-second TTL must not produce a zero reaper period (which {@code scheduleAtFixedRate}
 * rejects with {@link IllegalArgumentException}).
 */
class InMemoryPendingSessionStoreTest {

  private static ServerAuthState state() {
    return new ServerAuthState(new byte[32], new byte[32]);
  }

  @Test
  void storeAndRemove_roundTrip() {
    InMemoryPendingSessionStore store = new InMemoryPendingSessionStore();
    try {
      store.store("token-1", state(), "Y3JlZDE=", 3);
      assertThat(store.remove("token-1")).hasValueSatisfying(s -> {
        assertThat(s.credentialIdentifierBase64()).isEqualTo("Y3JlZDE=");
        assertThat(s.keyVersion()).isEqualTo(3);
      });
    } finally {
      store.shutdown();
    }
  }

  @Test
  void remove_isConsumeOnce() {
    InMemoryPendingSessionStore store = new InMemoryPendingSessionStore();
    try {
      store.store("token-1", state(), "Y3JlZDE=");
      assertThat(store.remove("token-1")).isPresent();
      assertThat(store.remove("token-1")).isEmpty();
    } finally {
      store.shutdown();
    }
  }

  @Test
  void remove_unknownToken_returnsEmpty() {
    InMemoryPendingSessionStore store = new InMemoryPendingSessionStore();
    try {
      assertThat(store.remove("nonexistent")).isEmpty();
    } finally {
      store.shutdown();
    }
  }

  @Test
  void expiredSession_returnsEmpty() throws InterruptedException {
    InMemoryPendingSessionStore store = new InMemoryPendingSessionStore(1, 100);
    try {
      store.store("token-1", state(), "Y3JlZDE=");
      Thread.sleep(1100);
      assertThat(store.remove("token-1")).isEmpty();
    } finally {
      store.shutdown();
    }
  }

  @Test
  void capacityLimit_throwsIllegalStateException() {
    InMemoryPendingSessionStore store = new InMemoryPendingSessionStore(600, 2);
    try {
      store.store("t1", state(), "a");
      store.store("t2", state(), "b");
      assertThatThrownBy(() -> store.store("t3", state(), "c"))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("Too many pending sessions");
    } finally {
      store.shutdown();
    }
  }

  @Test
  void shortTtl_doesNotProduceZeroReaperPeriod() {
    // Regression: ttlSeconds=1 means ttl/4 == 0; the Math.max(1, ...) guard must keep the reaper
    // period positive so scheduleAtFixedRate does not throw IllegalArgumentException at construction.
    assertThatCode(() -> {
      InMemoryPendingSessionStore store = new InMemoryPendingSessionStore(1, 10);
      store.shutdown();
    }).doesNotThrowAnyException();
  }
}
