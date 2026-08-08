package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ClientRegistrationStateTest {

  @Test
  void close_zerosTheRecordsOwnCopy() {
    byte[] password = {1, 2, 3};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);

    state.close();

    assertThat(state.password()).containsOnly((byte) 0);
  }

  /** See {@link ClientAuthStateTest#close_doesNotTouchTheCallersArray()} for why this matters. */
  @Test
  void close_doesNotTouchTheCallersArray() {
    byte[] password = {1, 2, 3};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);

    state.close();

    assertThat(password).containsExactly(1, 2, 3);
  }

  @Test
  void mutatingTheCallersArrayAfterConstruction_doesNotAffectTheState() {
    byte[] password = {7, 7};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);

    password[0] = 99;

    assertThat(state.password()).containsExactly(7, 7);
  }

  @Test
  void tryWithResources_zerosTheCopyOnExit() {
    byte[] password = {10, 20};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);

    ClientRegistrationState escaped;
    try (ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req)) {
      assertThat(state.password()).containsExactly(10, 20);
      escaped = state;
    }

    assertThat(escaped.password()).containsOnly((byte) 0);
    assertThat(password).containsExactly(10, 20);
  }

  @Test
  void recordAccessors_returnCorrectValues() {
    BigInteger blind = BigInteger.valueOf(7);
    byte[] password = {5};
    RegistrationRequest req = new RegistrationRequest(new byte[1]);
    ClientRegistrationState state = new ClientRegistrationState(blind, password, req);

    assertThat(state.blind()).isEqualTo(blind);
    assertThat(state.password()).isNotSameAs(password).containsExactly(5);
    assertThat(state.request()).isSameAs(req);
  }
}
