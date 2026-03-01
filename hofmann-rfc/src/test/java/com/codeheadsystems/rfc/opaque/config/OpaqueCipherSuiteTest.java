package com.codeheadsystems.rfc.opaque.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class OpaqueCipherSuiteTest {

  // --- Size constants ---

  static Stream<Arguments> suiteConstants() {
    return Stream.of(
        // suite, Npk, Nsk, Nh, Nn
        Arguments.of(OpaqueCipherSuite.P256_SHA256, 33, 32, 32, 32),
        Arguments.of(OpaqueCipherSuite.P384_SHA384, 49, 48, 48, 32),
        Arguments.of(OpaqueCipherSuite.P521_SHA512, 67, 66, 64, 32)
    );
  }

  @ParameterizedTest
  @MethodSource("suiteConstants")
  void sizeConstants(OpaqueCipherSuite suite, int npk, int nsk, int nh, int nn) {
    assertThat(suite.Npk()).isEqualTo(npk);
    assertThat(suite.Nsk()).isEqualTo(nsk);
    assertThat(suite.Nh()).isEqualTo(nh);
    assertThat(suite.Nn()).isEqualTo(nn);
  }

  @Test
  void p256_derivedSizes() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    assertThat(s.Nm()).isEqualTo(s.Nh());
    assertThat(s.Nx()).isEqualTo(s.Nh());
    assertThat(s.Noe()).isEqualTo(s.Npk());
    assertThat(s.Nok()).isEqualTo(s.Nsk());
    assertThat(s.envelopeSize()).isEqualTo(s.Nn() + s.Nm());
    assertThat(s.maskedResponseSize()).isEqualTo(s.Npk() + s.envelopeSize());
  }

  // --- fromName ---

  @ParameterizedTest
  @ValueSource(strings = {"P256_SHA256", "P384_SHA384", "P521_SHA512"})
  void fromName_validNames_returnCorrectSuite(String name) {
    OpaqueCipherSuite suite = OpaqueCipherSuite.fromName(name);
    assertThat(suite).isNotNull();
  }

  @Test
  void fromName_unknownName_throwsIAE() {
    assertThatThrownBy(() -> OpaqueCipherSuite.fromName("INVALID"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown OPAQUE cipher suite");
  }

  // --- hkdfExtract ---

  @Test
  void hkdfExtract_producesCorrectLength() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] prk = s.hkdfExtract(null, "input".getBytes(StandardCharsets.UTF_8));
    assertThat(prk).hasSize(s.Nh());
  }

  @Test
  void hkdfExtract_emptySalt_sameAsNullSalt() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] ikm = "test".getBytes(StandardCharsets.UTF_8);
    byte[] withNull = s.hkdfExtract(null, ikm);
    byte[] withEmpty = s.hkdfExtract(new byte[0], ikm);
    assertThat(withNull).isEqualTo(withEmpty);
  }

  @Test
  void hkdfExtract_withSalt_isDeterministic() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
    byte[] ikm = "ikm".getBytes(StandardCharsets.UTF_8);
    assertThat(s.hkdfExtract(salt, ikm)).isEqualTo(s.hkdfExtract(salt, ikm));
  }

  @Test
  void hkdfExtract_differentSalts_differentOutput() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] ikm = "ikm".getBytes(StandardCharsets.UTF_8);
    byte[] r1 = s.hkdfExtract("salt1".getBytes(StandardCharsets.UTF_8), ikm);
    byte[] r2 = s.hkdfExtract("salt2".getBytes(StandardCharsets.UTF_8), ikm);
    assertThat(r1).isNotEqualTo(r2);
  }

  // --- hkdfExpand ---

  @Test
  void hkdfExpand_producesRequestedLength() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] prk = new byte[32];
    prk[0] = 1;
    byte[] info = "info".getBytes(StandardCharsets.UTF_8);
    assertThat(s.hkdfExpand(prk, info, 16)).hasSize(16);
    assertThat(s.hkdfExpand(prk, info, 32)).hasSize(32);
    assertThat(s.hkdfExpand(prk, info, 64)).hasSize(64);
  }

  @Test
  void hkdfExpand_isDeterministic() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] prk = new byte[32];
    prk[0] = 1;
    byte[] info = "info".getBytes(StandardCharsets.UTF_8);
    assertThat(s.hkdfExpand(prk, info, 32)).isEqualTo(s.hkdfExpand(prk, info, 32));
  }

  // --- hkdfExpandLabel ---

  @Test
  void hkdfExpandLabel_producesRequestedLength() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] secret = new byte[32];
    secret[0] = 1;
    byte[] label = "HandshakeSecret".getBytes(StandardCharsets.US_ASCII);
    byte[] context = new byte[0];
    byte[] result = s.hkdfExpandLabel(secret, label, context, 32);
    assertThat(result).hasSize(32);
  }

  // --- hash / hmac delegation ---

  @Test
  void hash_producesCorrectLength() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] result = s.hash("test".getBytes(StandardCharsets.UTF_8));
    assertThat(result).hasSize(s.Nh());
  }

  @Test
  void hmac_producesCorrectLength() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] result = s.hmac(new byte[32], "test".getBytes(StandardCharsets.UTF_8));
    assertThat(result).hasSize(s.Nh());
  }

  // --- deserializePoint ---

  @Test
  void deserializePoint_validGenerator_succeeds() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] gen = s.oprfSuite().groupSpec().scalarMultiplyGenerator(BigInteger.ONE);
    assertThat(s.deserializePoint(gen)).isNotNull();
    assertThat(s.deserializePoint(gen).isInfinity()).isFalse();
  }

  // --- deriveAkeKeyPair ---

  @Test
  void deriveAkeKeyPair_producesValidKeyPair() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] seed = new byte[32];
    seed[0] = 42;
    OpaqueCipherSuite.AkeKeyPair kp = s.deriveAkeKeyPair(seed);
    assertThat(kp.privateKey()).isGreaterThan(BigInteger.ZERO);
    assertThat(kp.privateKey()).isLessThan(s.oprfSuite().groupSpec().groupOrder());
    assertThat(kp.publicKeyBytes()).hasSize(s.Npk());
    assertThat(kp.publicKeyBytes()[0]).isIn((byte) 0x02, (byte) 0x03);
  }

  @Test
  void deriveAkeKeyPair_isDeterministic() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] seed = "deterministic-seed".getBytes(StandardCharsets.UTF_8);
    OpaqueCipherSuite.AkeKeyPair kp1 = s.deriveAkeKeyPair(seed);
    OpaqueCipherSuite.AkeKeyPair kp2 = s.deriveAkeKeyPair(seed);
    assertThat(kp1.privateKey()).isEqualTo(kp2.privateKey());
    assertThat(kp1.publicKeyBytes()).isEqualTo(kp2.publicKeyBytes());
  }
}
