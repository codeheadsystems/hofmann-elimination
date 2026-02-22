package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ClientAuthStateTest {

  @Test
  void close_zerosPassword() {
    byte[] password = {1, 2, 3, 4, 5};
    KE1 ke1 = new KE1(new CredentialRequest(new byte[33]), new byte[32], new byte[33]);
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1, BigInteger.TEN);

    state.close();

    assertThat(password).containsOnly((byte) 0);
  }

  @Test
  void tryWithResources_zerosPassword() {
    byte[] password = {10, 20, 30};
    KE1 ke1 = new KE1(new CredentialRequest(new byte[33]), new byte[32], new byte[33]);

    try (ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1, BigInteger.TEN)) {
      assertThat(state.password()).containsExactly(10, 20, 30);
    }

    assertThat(password).containsOnly((byte) 0);
  }

  @Test
  void recordAccessors_returnCorrectValues() {
    BigInteger blind = BigInteger.valueOf(42);
    byte[] password = {1};
    KE1 ke1 = new KE1(new CredentialRequest(new byte[1]), new byte[1], new byte[1]);
    BigInteger akePriv = BigInteger.valueOf(99);
    ClientAuthState state = new ClientAuthState(blind, password, ke1, akePriv);

    assertThat(state.blind()).isEqualTo(blind);
    assertThat(state.password()).isSameAs(password);
    assertThat(state.ke1()).isSameAs(ke1);
    assertThat(state.clientAkePrivateKey()).isEqualTo(akePriv);
  }
}
