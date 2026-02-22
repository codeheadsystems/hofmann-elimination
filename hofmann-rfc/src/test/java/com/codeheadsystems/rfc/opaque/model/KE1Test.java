package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class KE1Test {

  @Test
  void serialize_concatenatesFieldsInOrder() {
    byte[] blinded = {0x01, 0x02, 0x03};
    byte[] nonce = {0x04, 0x05};
    byte[] akePk = {0x06, 0x07, 0x08};
    KE1 ke1 = new KE1(new CredentialRequest(blinded), nonce, akePk);

    byte[] wire = ke1.serialize();

    assertThat(wire).isEqualTo(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
  }

  @Test
  void serialize_length_isSumOfFields() {
    byte[] blinded = new byte[33];
    byte[] nonce = new byte[32];
    byte[] akePk = new byte[33];
    KE1 ke1 = new KE1(new CredentialRequest(blinded), nonce, akePk);

    assertThat(ke1.serialize()).hasSize(33 + 32 + 33);
  }

  @Test
  void serialize_sentinelBytes_atCorrectOffsets() {
    byte[] blinded = new byte[33];
    byte[] nonce = new byte[32];
    byte[] akePk = new byte[33];
    java.util.Arrays.fill(blinded, (byte) 0xAA);
    java.util.Arrays.fill(nonce, (byte) 0xBB);
    java.util.Arrays.fill(akePk, (byte) 0xCC);
    KE1 ke1 = new KE1(new CredentialRequest(blinded), nonce, akePk);

    byte[] wire = ke1.serialize();

    // Check boundaries
    assertThat(wire[0]).isEqualTo((byte) 0xAA);
    assertThat(wire[32]).isEqualTo((byte) 0xAA);
    assertThat(wire[33]).isEqualTo((byte) 0xBB);
    assertThat(wire[64]).isEqualTo((byte) 0xBB);
    assertThat(wire[65]).isEqualTo((byte) 0xCC);
    assertThat(wire[97]).isEqualTo((byte) 0xCC);
  }
}
