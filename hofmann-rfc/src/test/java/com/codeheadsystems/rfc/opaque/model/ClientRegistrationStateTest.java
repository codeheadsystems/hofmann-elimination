package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ClientRegistrationStateTest {

  @Test
  void close_zerosPassword() {
    byte[] password = {1, 2, 3};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);

    state.close();

    assertThat(password).containsOnly((byte) 0);
  }

  @Test
  void tryWithResources_zerosPassword() {
    byte[] password = {10, 20};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);

    try (ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req)) {
      assertThat(state.password()).containsExactly(10, 20);
    }

    assertThat(password).containsOnly((byte) 0);
  }

  @Test
  void recordAccessors_returnCorrectValues() {
    BigInteger blind = BigInteger.valueOf(7);
    byte[] password = {5};
    RegistrationRequest req = new RegistrationRequest(new byte[1]);
    ClientRegistrationState state = new ClientRegistrationState(blind, password, req);

    assertThat(state.blind()).isEqualTo(blind);
    assertThat(state.password()).isSameAs(password);
    assertThat(state.request()).isSameAs(req);
  }
}
