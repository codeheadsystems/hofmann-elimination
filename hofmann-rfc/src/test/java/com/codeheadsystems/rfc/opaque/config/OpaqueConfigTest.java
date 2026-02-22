package com.codeheadsystems.rfc.opaque.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.common.RandomProvider;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class OpaqueConfigTest {

  // --- Factory methods ---

  @Test
  void default_usesP256AndArgon2() {
    OpaqueConfig config = OpaqueConfig.DEFAULT;
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P256_SHA256);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.Argon2idKsf.class);
    assertThat(config.argon2Memory()).isEqualTo(65536);
    assertThat(config.argon2Iterations()).isEqualTo(3);
    assertThat(config.argon2Parallelism()).isEqualTo(1);
  }

  @Test
  void forTesting_usesIdentityKsf() {
    OpaqueConfig config = OpaqueConfig.forTesting();
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P256_SHA256);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.IdentityKsf.class);
    assertThat(config.context()).isEqualTo("OPAQUE-POC".getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  void forTesting_withSuite_usesGivenSuite() {
    OpaqueConfig config = OpaqueConfig.forTesting(OpaqueCipherSuite.P384_SHA384);
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P384_SHA384);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.IdentityKsf.class);
  }

  @Test
  void withArgon2id_noSuite_usesP256() {
    byte[] ctx = "test-context".getBytes(StandardCharsets.UTF_8);
    OpaqueConfig config = OpaqueConfig.withArgon2id(ctx, 1024, 1, 1);
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P256_SHA256);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.Argon2idKsf.class);
    assertThat(config.argon2Memory()).isEqualTo(1024);
    assertThat(config.argon2Iterations()).isEqualTo(1);
    assertThat(config.argon2Parallelism()).isEqualTo(1);
    assertThat(config.context()).isEqualTo(ctx);
  }

  @Test
  void withArgon2id_withSuite_usesGivenSuite() {
    byte[] ctx = "test".getBytes(StandardCharsets.UTF_8);
    OpaqueConfig config = OpaqueConfig.withArgon2id(
        OpaqueCipherSuite.P384_SHA384, ctx, 2048, 2, 4);
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P384_SHA384);
    assertThat(config.argon2Memory()).isEqualTo(2048);
  }

  // --- withRandomConfig ---

  @Test
  void withRandomConfig_preservesOtherFields() {
    OpaqueConfig original = OpaqueConfig.forTesting();
    RandomProvider rp = new RandomProvider();
    OpaqueConfig copy = original.withRandomConfig(rp);
    assertThat(copy.randomProvider()).isSameAs(rp);
    assertThat(copy.cipherSuite()).isSameAs(original.cipherSuite());
    assertThat(copy.ksf()).isSameAs(original.ksf());
    assertThat(copy.context()).isEqualTo(original.context());
  }

  // --- Size delegates ---

  @Test
  void sizeDelegates_matchCipherSuite() {
    OpaqueConfig config = OpaqueConfig.forTesting();
    OpaqueCipherSuite cs = config.cipherSuite();
    assertThat(config.Nm()).isEqualTo(cs.Nm());
    assertThat(config.Nh()).isEqualTo(cs.Nh());
    assertThat(config.Nx()).isEqualTo(cs.Nx());
    assertThat(config.Npk()).isEqualTo(cs.Npk());
    assertThat(config.Nsk()).isEqualTo(cs.Nsk());
    assertThat(config.Noe()).isEqualTo(cs.Noe());
    assertThat(config.Nok()).isEqualTo(cs.Nok());
    assertThat(config.envelopeSize()).isEqualTo(cs.envelopeSize());
    assertThat(config.maskedResponseSize()).isEqualTo(cs.maskedResponseSize());
  }

  @Test
  void nn_isAlways32() {
    assertThat(OpaqueConfig.Nn).isEqualTo(32);
  }

  // --- IdentityKsf ---

  @Test
  void identityKsf_returnsInputUnchanged() {
    OpaqueConfig.IdentityKsf ksf = new OpaqueConfig.IdentityKsf();
    byte[] input = {1, 2, 3, 4, 5};
    byte[] result = ksf.stretch(input, OpaqueConfig.forTesting());
    assertThat(result).isSameAs(input);
  }

  // --- Argon2idKsf ---

  @Test
  void argon2idKsf_producesCorrectLengthOutput() {
    OpaqueConfig config = OpaqueConfig.withArgon2id(
        "ctx".getBytes(StandardCharsets.UTF_8), 1024, 1, 1);
    byte[] input = "password".getBytes(StandardCharsets.UTF_8);
    byte[] result = config.ksf().stretch(input, config);
    assertThat(result).hasSize(config.Nh());
  }

  @Test
  void argon2idKsf_isDeterministic() {
    OpaqueConfig config = OpaqueConfig.withArgon2id(
        "ctx".getBytes(StandardCharsets.UTF_8), 1024, 1, 1);
    byte[] input = "password".getBytes(StandardCharsets.UTF_8);
    byte[] r1 = config.ksf().stretch(input, config);
    byte[] r2 = config.ksf().stretch(input, config);
    assertThat(r1).isEqualTo(r2);
  }
}
