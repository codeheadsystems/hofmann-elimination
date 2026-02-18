package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InMemorySessionStoreTest {

  private InMemorySessionStore store;

  @BeforeEach
  void setUp() {
    store = new InMemorySessionStore();
  }

  @Test
  void storeAndLoad_roundTrip() {
    SessionData data = new SessionData("cred", "key", Instant.now(), Instant.now().plusSeconds(3600));
    store.store("jti-1", data);

    Optional<SessionData> loaded = store.load("jti-1");
    assertThat(loaded).isPresent().contains(data);
  }

  @Test
  void load_notFound_returnsEmpty() {
    assertThat(store.load("nonexistent")).isEmpty();
  }

  @Test
  void load_expired_returnsEmpty() {
    SessionData data = new SessionData("cred", "key",
        Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
    store.store("jti-expired", data);

    assertThat(store.load("jti-expired")).isEmpty();
  }

  @Test
  void revoke_removesSession() {
    SessionData data = new SessionData("cred", "key", Instant.now(), Instant.now().plusSeconds(3600));
    store.store("jti-revoke", data);

    store.revoke("jti-revoke");
    assertThat(store.load("jti-revoke")).isEmpty();
  }
}
