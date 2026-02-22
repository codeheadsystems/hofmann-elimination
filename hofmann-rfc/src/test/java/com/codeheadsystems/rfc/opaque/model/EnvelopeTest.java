package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class EnvelopeTest {

  // --- serialize ---

  @Test
  void serialize_concatenatesNonceAndTag() {
    byte[] nonce = {1, 2, 3};
    byte[] tag = {4, 5, 6, 7};
    Envelope env = new Envelope(nonce, tag);
    byte[] wire = env.serialize();
    assertThat(wire).isEqualTo(new byte[]{1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  void serialize_emptyNonceAndTag() {
    Envelope env = new Envelope(new byte[0], new byte[0]);
    assertThat(env.serialize()).isEmpty();
  }

  // --- deserialize ---

  @Test
  void deserialize_extractsFieldsAtCorrectOffsets() {
    byte[] data = {0, 0, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0};
    // offset=2, nonceLen=2, tagLen=3 → nonce=[0A,0B], tag=[0C,0D,0E]
    Envelope env = Envelope.deserialize(data, 2, 2, 3);
    assertThat(env.envelopeNonce()).isEqualTo(new byte[]{0x0A, 0x0B});
    assertThat(env.authTag()).isEqualTo(new byte[]{0x0C, 0x0D, 0x0E});
  }

  @Test
  void deserialize_atOffsetZero() {
    byte[] data = {1, 2, 3, 4, 5};
    Envelope env = Envelope.deserialize(data, 0, 3, 2);
    assertThat(env.envelopeNonce()).isEqualTo(new byte[]{1, 2, 3});
    assertThat(env.authTag()).isEqualTo(new byte[]{4, 5});
  }

  @Test
  void deserialize_nullBytes_throwsIAE() {
    assertThatThrownBy(() -> Envelope.deserialize(null, 0, 32, 32))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("too short");
  }

  @Test
  void deserialize_tooShort_throwsIAE() {
    byte[] data = new byte[10];
    assertThatThrownBy(() -> Envelope.deserialize(data, 0, 32, 32))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("too short");
  }

  @Test
  void deserialize_tooShortWithOffset_throwsIAE() {
    byte[] data = new byte[64];
    // offset=1 means we need 1 + 32 + 32 = 65 bytes
    assertThatThrownBy(() -> Envelope.deserialize(data, 1, 32, 32))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("too short");
  }

  // --- roundTrip ---

  @Test
  void serializeDeserialize_roundTrip() {
    byte[] nonce = {10, 20, 30, 40};
    byte[] tag = {50, 60, 70, 80, 90};
    Envelope original = new Envelope(nonce, tag);
    byte[] wire = original.serialize();
    Envelope restored = Envelope.deserialize(wire, 0, nonce.length, tag.length);
    assertThat(restored.envelopeNonce()).isEqualTo(nonce);
    assertThat(restored.authTag()).isEqualTo(tag);
  }
}
