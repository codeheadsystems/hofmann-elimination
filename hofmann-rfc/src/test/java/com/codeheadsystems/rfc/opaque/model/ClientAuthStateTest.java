package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ClientAuthStateTest {

  private static KE1 ke1() {
    return new KE1(new CredentialRequest(new byte[33]), new byte[32], new byte[33]);
  }

  @Test
  void close_zerosTheRecordsOwnCopy() {
    byte[] password = {1, 2, 3, 4, 5};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);

    state.close();

    assertThat(state.password()).containsOnly((byte) 0);
  }

  /**
   * The behaviour that makes the {@link AutoCloseable} usable at all.
   *
   * <p>These previously asserted the opposite — that {@code close()} zeroed the caller's array —
   * and that is exactly why nothing in {@code src/main} could call it: {@code authenticate()}
   * hands the same password to {@code changePassword} afterwards on the key-rotation path, so
   * closing would have destroyed a live buffer. The copy is what lets the callers close.
   */
  @Test
  void close_doesNotTouchTheCallersArray() {
    byte[] password = {1, 2, 3, 4, 5};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);

    state.close();

    assertThat(password).containsExactly(1, 2, 3, 4, 5);
  }

  @Test
  void mutatingTheCallersArrayAfterConstruction_doesNotAffectTheState() {
    byte[] password = {7, 7, 7};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);

    password[0] = 99;

    // The copy is taken at construction, so the blind already computed from the original bytes
    // stays consistent with what the state reports.
    assertThat(state.password()).containsExactly(7, 7, 7);
  }

  @Test
  void tryWithResources_zerosTheCopyOnExit() {
    byte[] password = {10, 20, 30};

    ClientAuthState escaped;
    try (ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN)) {
      assertThat(state.password()).containsExactly(10, 20, 30);
      escaped = state;
    }

    assertThat(escaped.password()).containsOnly((byte) 0);
    assertThat(password).containsExactly(10, 20, 30);
  }

  @Test
  void recordAccessors_returnCorrectValues() {
    BigInteger blind = BigInteger.valueOf(42);
    byte[] password = {1};
    KE1 ke1 = new KE1(new CredentialRequest(new byte[1]), new byte[1], new byte[1]);
    BigInteger akePriv = BigInteger.valueOf(99);
    ClientAuthState state = new ClientAuthState(blind, password, ke1, akePriv);

    assertThat(state.blind()).isEqualTo(blind);
    // Copied, not aliased — the identity assertion here is the point, not incidental.
    assertThat(state.password()).isNotSameAs(password).containsExactly(1);
    assertThat(state.ke1()).isSameAs(ke1);
    assertThat(state.clientAkePrivateKey()).isEqualTo(akePriv);
  }
}
