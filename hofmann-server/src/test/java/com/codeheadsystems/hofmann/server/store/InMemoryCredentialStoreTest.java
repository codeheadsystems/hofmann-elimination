package com.codeheadsystems.hofmann.server.store;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link InMemoryCredentialStore}, focusing on the {@code ByteKey} wrapper's
 * value-based equals/hashCode (so a credential stored under one {@code byte[]} instance can be
 * retrieved with a different instance holding the same bytes) and the versioned round-trip.
 */
class InMemoryCredentialStoreTest {

  private InMemoryCredentialStore store;

  private static RegistrationRecord record() {
    return new RegistrationRecord(new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
  }

  @BeforeEach
  void setUp() {
    store = new InMemoryCredentialStore();
  }

  @Test
  void load_withDifferentByteArrayInstance_findsRecordByValue() {
    byte[] keyStored = "alice@example.com".getBytes(StandardCharsets.UTF_8);
    byte[] keyLookup = "alice@example.com".getBytes(StandardCharsets.UTF_8);
    // Distinct array instances with identical contents must hash/compare equal.
    assertThat(keyStored).isNotSameAs(keyLookup).isEqualTo(keyLookup);

    RegistrationRecord record = record();
    store.store(keyStored, record);

    assertThat(store.load(keyLookup)).hasValue(record);
  }

  @Test
  void load_unknownCredential_returnsEmpty() {
    assertThat(store.load("nobody".getBytes(StandardCharsets.UTF_8))).isEmpty();
  }

  @Test
  void storeVersioned_loadVersioned_roundTrip() {
    byte[] key = "bob".getBytes(StandardCharsets.UTF_8);
    RegistrationRecord record = record();
    store.store(key, record, 7);

    byte[] lookup = "bob".getBytes(StandardCharsets.UTF_8);
    assertThat(store.loadVersioned(lookup)).hasValueSatisfying(vc -> {
      assertThat(vc.keyVersion()).isEqualTo(7);
      assertThat(vc.record()).isEqualTo(record);
    });
  }

  @Test
  void store_defaultsToKeyVersionZero() {
    byte[] key = "carol".getBytes(StandardCharsets.UTF_8);
    store.store(key, record());
    assertThat(store.loadVersioned(key)).hasValueSatisfying(vc ->
        assertThat(vc.keyVersion()).isZero());
  }

  @Test
  void storeIfAbsent_onUnregisteredCredential_storesAndReportsTrue() {
    byte[] key = "erin".getBytes(StandardCharsets.UTF_8);
    RegistrationRecord record = record();

    assertThat(store.storeIfAbsent(key, record, 3)).isTrue();
    assertThat(store.loadVersioned("erin".getBytes(StandardCharsets.UTF_8)))
        .hasValueSatisfying(vc -> {
          assertThat(vc.keyVersion()).isEqualTo(3);
          assertThat(vc.record()).isEqualTo(record);
        });
  }

  @Test
  void storeIfAbsent_onRegisteredCredential_reportsFalseAndLeavesRecordUntouched() {
    byte[] key = "frank".getBytes(StandardCharsets.UTF_8);
    RegistrationRecord original = record();
    store.store(key, original, 1);

    RegistrationRecord takeover = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    assertThat(store.storeIfAbsent("frank".getBytes(StandardCharsets.UTF_8), takeover, 9))
        .isFalse();

    // The account-takeover property: the existing record and its key version both survive.
    assertThat(store.loadVersioned(key)).hasValueSatisfying(vc -> {
      assertThat(vc.keyVersion()).isEqualTo(1);
      assertThat(vc.record()).isSameAs(original);
    });
  }

  @Test
  void storeIfAbsent_underConcurrency_letsExactlyOneWriterWin() throws Exception {
    // The check-then-act this replaces let two concurrent registrations for the same identifier
    // both observe "absent" and both write, so the second silently took the account over.
    for (int round = 0; round < 200; round++) {
      InMemoryCredentialStore fresh = new InMemoryCredentialStore();
      byte[] key = ("grace-" + round).getBytes(StandardCharsets.UTF_8);
      int writers = 8;
      java.util.concurrent.CyclicBarrier barrier =
          new java.util.concurrent.CyclicBarrier(writers);
      java.util.concurrent.atomic.AtomicInteger wins =
          new java.util.concurrent.atomic.AtomicInteger();
      Thread[] threads = new Thread[writers];
      for (int i = 0; i < writers; i++) {
        threads[i] = new Thread(() -> {
          try {
            barrier.await();
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
          if (fresh.storeIfAbsent(key.clone(), record(), 0)) {
            wins.incrementAndGet();
          }
        });
        threads[i].start();
      }
      for (Thread t : threads) {
        t.join();
      }
      assertThat(wins.get())
          .withFailMessage("round %d: %d writers stored the same credential identifier; "
              + "exactly one must win", round, wins.get())
          .isEqualTo(1);
    }
  }

  @Test
  void delete_removesRecord() {
    byte[] key = "dave".getBytes(StandardCharsets.UTF_8);
    store.store(key, record());
    assertThat(store.load(key)).isPresent();

    store.delete("dave".getBytes(StandardCharsets.UTF_8));

    assertThat(store.load(key)).isEmpty();
    assertThat(store.loadVersioned(key)).isEmpty();
  }
}
