package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The type In memory session store test.
 */
class InMemorySessionStoreTest {

  private InMemorySessionStore store;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    store = new InMemorySessionStore();
  }

  /**
   * Store and load round trip.
   */
  @Test
  void storeAndLoad_roundTrip() {
    SessionData data = new SessionData("cred", "key", Instant.now(), Instant.now().plusSeconds(3600));
    store.store("jti-1", data);

    Optional<SessionData> loaded = store.load("jti-1");
    assertThat(loaded).isPresent().contains(data);
  }

  /**
   * Load not found returns empty.
   */
  @Test
  void load_notFound_returnsEmpty() {
    assertThat(store.load("nonexistent")).isEmpty();
  }

  /**
   * Load expired returns empty.
   */
  @Test
  void load_expired_returnsEmpty() {
    SessionData data = new SessionData("cred", "key",
        Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
    store.store("jti-expired", data);

    assertThat(store.load("jti-expired")).isEmpty();
  }

  /**
   * Revoke removes session.
   */
  @Test
  void revoke_removesSession() {
    SessionData data = new SessionData("cred", "key", Instant.now(), Instant.now().plusSeconds(3600));
    store.store("jti-revoke", data);

    store.revoke("jti-revoke");
    assertThat(store.load("jti-revoke")).isEmpty();
  }

  /**
   * Revoke by credential identifier removes all sessions for that credential and leaves others intact.
   */
  @Test
  void revokeByCredentialIdentifier_removesAllSessionsForCredential_leavesOthersIntact() {
    Instant expiry = Instant.now().plusSeconds(3600);
    store.store("jti-a1", new SessionData("cred-a", "key", Instant.now(), expiry));
    store.store("jti-a2", new SessionData("cred-a", "key", Instant.now(), expiry));
    store.store("jti-b1", new SessionData("cred-b", "key", Instant.now(), expiry));

    store.revokeByCredentialIdentifier("cred-a");

    assertThat(store.load("jti-a1")).isEmpty();
    assertThat(store.load("jti-a2")).isEmpty();
    assertThat(store.load("jti-b1")).isPresent();
  }

  /**
   * Revoke by credential identifier for unknown credential does not throw.
   */
  @Test
  void revokeByCredentialIdentifier_unknownCredential_doesNotThrow() {
    assertThatCode(() -> store.revokeByCredentialIdentifier("nonexistent"))
        .doesNotThrowAnyException();
  }
}
