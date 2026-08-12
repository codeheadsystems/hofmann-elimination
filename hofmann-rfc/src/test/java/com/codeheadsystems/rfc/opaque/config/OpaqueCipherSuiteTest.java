package com.codeheadsystems.rfc.opaque.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;
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

  /**
   * Asserts which suite came back. The previous version asserted only isNotNull, which a
   * fromName returning P-256 for every input would have satisfied — on a method whose entire job
   * is to tell the suites apart.
   */
  @ParameterizedTest
  @MethodSource("namedSuites")
  void fromName_validNames_returnThatSameSuite(String name, OpaqueCipherSuite expected) {
    assertThat(OpaqueCipherSuite.fromName(name)).isSameAs(expected);
  }

  static Stream<Arguments> namedSuites() {
    return Stream.of(
        Arguments.of("P256_SHA256", OpaqueCipherSuite.P256_SHA256),
        Arguments.of("P384_SHA384", OpaqueCipherSuite.P384_SHA384),
        Arguments.of("P521_SHA512", OpaqueCipherSuite.P521_SHA512),
        Arguments.of("RISTRETTO255_SHA512", OpaqueCipherSuite.RISTRETTO255_SHA512));
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

  // Removed: hkdfExtract_withSalt_isDeterministic and hkdfExpand_isDeterministic, which each
  // invoked the function twice and compared the results to each other. That proves the function
  // is a function; it holds for any output at all, including a wrong one. This file's other HKDF
  // assertions were length-only, so nothing here pinned a single HKDF byte — a swapped
  // Extract/Expand or a wrong label prefix was caught only indirectly, downstream, by the OPAQUE
  // vectors. The RFC 5869 known-answer vectors below replace them.

  /**
   * RFC 5869 Appendix A.1 — basic HKDF-SHA-256 case.
   *
   * <p>Both halves are pinned separately: {@code hkdfExtract} against the published PRK, then
   * {@code hkdfExpand} against the published OKM, so a fault in either is attributed rather than
   * cancelling out across the pair.
   */
  @Test
  void hkdfExtractAndExpand_matchRfc5869TestCase1() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    byte[] salt = Hex.decode("000102030405060708090a0b0c");
    byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");

    byte[] prk = s.hkdfExtract(salt, ikm);

    assertThat(Hex.toHexString(prk))
        .isEqualTo("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    assertThat(Hex.toHexString(s.hkdfExpand(prk, info, 42)))
        .isEqualTo("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            + "34007208d5b887185865");
  }

  /**
   * RFC 5869 Appendix A.2 — 80-byte inputs and an 82-byte output, so the expand loop runs to
   * T(3) rather than stopping inside the first block.
   */
  @Test
  void hkdfExtractAndExpand_matchRfc5869TestCase2() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] ikm = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        + "404142434445464748494a4b4c4d4e4f");
    byte[] salt = Hex.decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    byte[] info = Hex.decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    byte[] prk = s.hkdfExtract(salt, ikm);

    assertThat(Hex.toHexString(prk))
        .isEqualTo("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    assertThat(Hex.toHexString(s.hkdfExpand(prk, info, 82)))
        .isEqualTo("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            + "cc30c58179ec3e87c14c01d5c1f3434f1d87");
  }

  /**
   * RFC 5869 Appendix A.3 — zero-length salt and info. This is the case
   * {@code hkdfExtract_emptySalt_sameAsNullSalt} above compares against itself; here the shared
   * value is pinned to the published PRK, so "both are equal" also means "both are correct".
   */
  @Test
  void hkdfExtractAndExpand_matchRfc5869TestCase3_emptySaltAndInfo() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    byte[] prk = s.hkdfExtract(new byte[0], ikm);

    assertThat(Hex.toHexString(prk))
        .isEqualTo("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    assertThat(Hex.toHexString(s.hkdfExpand(prk, new byte[0], 42)))
        .isEqualTo("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            + "9d201395faa4b61a96c8");
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

  /**
   * The generated {@code toString} printed the private key in full decimal, and this is the
   * widest-reach instance of that mistake in the library: a public nested record on a public class,
   * returned by {@code deriveAkeKeyPair} for the client's ephemeral AKE key and the server's alike.
   * Disclosing either yields that session's Diffie-Hellman outputs. Pinned because redaction
   * regresses silently otherwise.
   */
  @Test
  void akeKeyPairToString_doesNotDiscloseThePrivateKey() {
    OpaqueCipherSuite s = OpaqueCipherSuite.P256_SHA256;
    OpaqueCipherSuite.AkeKeyPair kp =
        s.deriveAkeKeyPair("a-seed".getBytes(StandardCharsets.UTF_8));

    assertThat(kp.toString())
        .doesNotContain(kp.privateKey().toString())
        .contains("<redacted>");
  }
}
