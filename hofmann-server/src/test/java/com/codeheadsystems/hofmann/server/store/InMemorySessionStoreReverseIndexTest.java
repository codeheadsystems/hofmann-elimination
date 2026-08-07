package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for issue 6: the {@code credentialToJtis} reverse index in
 * {@link InMemorySessionStore} must stay in sync with the primary store.
 *
 * <p>Before the fix, a session that expired and was lazily evicted by {@link
 * InMemorySessionStore#load} left its jti behind in the reverse index, so the index grew
 * unbounded for sessions that expired without an explicit revoke.
 */
class InMemorySessionStoreReverseIndexTest {

  private InMemorySessionStore store;

  @BeforeEach
  void setUp() {
    store = new InMemorySessionStore();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Set<String>> reverseIndex() {
    try {
      Field field = InMemorySessionStore.class.getDeclaredField("credentialToJtis");
      field.setAccessible(true);
      return (Map<String, Set<String>>) field.get(store);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("could not read credentialToJtis", e);
    }
  }

  private static SessionData live(String cred) {
    return new SessionData(cred, Instant.now(), Instant.now().plusSeconds(3600));
  }

  private static SessionData expired(String cred) {
    return new SessionData(cred,
        Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
  }

  @Test
  void load_lazyEvictionOfExpiredSession_dropsJtiFromReverseIndex() {
    store.store("jti-expired", expired("cred"));
    // Index has the jti before eviction.
    assertThat(reverseIndex().get("cred")).contains("jti-expired");

    // Lazy eviction on load.
    assertThat(store.load("jti-expired")).isEmpty();

    // The sole jti is gone, so the credential's set is dropped entirely.
    assertThat(reverseIndex()).doesNotContainKey("cred");
  }

  @Test
  void load_lazyEvictionLeavesLiveSiblingJti() {
    store.store("jti-expired", expired("cred"));
    store.store("jti-live", live("cred"));

    assertThat(store.load("jti-expired")).isEmpty();

    // Only the expired jti is removed from the index; the live sibling remains.
    assertThat(reverseIndex().get("cred")).containsExactly("jti-live").doesNotContain("jti-expired");
    // And the live session is still loadable.
    assertThat(store.load("jti-live")).isPresent();
  }

  @Test
  void revoke_removesEmptySetFromReverseIndex() {
    store.store("jti-1", live("cred"));
    assertThat(reverseIndex()).containsKey("cred");

    store.revoke("jti-1");

    // Once the credential's last jti is revoked, its now-empty set is dropped.
    assertThat(reverseIndex()).doesNotContainKey("cred");
    assertThat(store.load("jti-1")).isEmpty();
  }

  @Test
  void revokeByCredentialIdentifier_afterEviction_revokesRemainingSession() {
    store.store("jti-expired", expired("cred"));
    store.store("jti-live", live("cred"));
    store.load("jti-expired"); // evict expired, sync index

    store.revokeByCredentialIdentifier("cred");

    assertThat(store.load("jti-live")).isEmpty();
    assertThat(reverseIndex()).doesNotContainKey("cred");
  }
}
