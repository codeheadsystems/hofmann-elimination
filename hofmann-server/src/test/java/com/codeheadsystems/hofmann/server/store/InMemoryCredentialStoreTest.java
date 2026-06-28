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
  void delete_removesRecord() {
    byte[] key = "dave".getBytes(StandardCharsets.UTF_8);
    store.store(key, record());
    assertThat(store.load(key)).isPresent();

    store.delete("dave".getBytes(StandardCharsets.UTF_8));

    assertThat(store.load(key)).isEmpty();
    assertThat(store.loadVersioned(key)).isEmpty();
  }
}
