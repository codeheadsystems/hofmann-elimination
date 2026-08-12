package com.codeheadsystems.rfc.oprf.rfc9497;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.oprf.IdentityEncodings;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

class OprfCipherSuiteTest {

  // --- Builder ---

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void builder_allSuites_createSuccessfully(CurveHashSuite suite) {
    OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
    assertThat(cs).isNotNull();
    assertThat(cs.groupSpec()).isNotNull();
    assertThat(cs.hashAlgorithm()).isNotNull();
    assertThat(cs.hashOutputLength()).isGreaterThan(0);
  }

  @Test
  void builder_defaultSuiteIsP256() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    assertThat(cs.identifier()).isEqualTo("P256-SHA256");
  }

  @Test
  void builder_withSuiteByName() {
    OprfCipherSuite cs = OprfCipherSuite.builder().withSuite("P384_SHA384").build();
    assertThat(cs.identifier()).isEqualTo("P384-SHA384");
  }

  @Test
  void builder_withRandom() {
    SecureRandom custom = new SecureRandom();
    OprfCipherSuite cs = OprfCipherSuite.builder().withRandom(custom).build();
    assertThat(cs.randomConfig().random()).isSameAs(custom);
  }

  @Test
  void builder_withRandomProvider() {
    RandomProvider rp = new RandomProvider(new SecureRandom());
    OprfCipherSuite cs = OprfCipherSuite.builder().withRandomProvider(rp).build();
    assertThat(cs.randomConfig()).isSameAs(rp);
  }

  // --- Identifier & suite properties ---

  static Stream<Arguments> suiteProperties() {
    return Stream.of(
        Arguments.of(CurveHashSuite.P256_SHA256, "P256-SHA256", "SHA-256", 32, 33),
        Arguments.of(CurveHashSuite.P384_SHA384, "P384-SHA384", "SHA-384", 48, 49),
        Arguments.of(CurveHashSuite.P521_SHA512, "P521-SHA512", "SHA-512", 64, 67)
    );
  }

  @ParameterizedTest
  @MethodSource("suiteProperties")
  void suiteProperties_areCorrect(CurveHashSuite suite, String id, String hashAlg,
                                   int hashLen, int elemSize) {
    OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
    assertThat(cs.identifier()).isEqualTo(id);
    assertThat(cs.hashAlgorithm()).isEqualTo(hashAlg);
    assertThat(cs.hashOutputLength()).isEqualTo(hashLen);
    assertThat(cs.elementSize()).isEqualTo(elemSize);
  }

  // --- DST strings ---

  @Test
  void dstStrings_containExpectedPrefixes() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    assertThat(new String(cs.hashToGroupDst(), StandardCharsets.UTF_8)).startsWith("HashToGroup-");
    assertThat(new String(cs.hashToScalarDst(), StandardCharsets.UTF_8)).startsWith("HashToScalar-");
    assertThat(new String(cs.deriveKeyPairDst(), StandardCharsets.UTF_8)).startsWith("DeriveKeyPair");
  }

  @Test
  void contextString_containsOPRFV1Prefix() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    String ctx = new String(cs.contextString(), StandardCharsets.UTF_8);
    assertThat(ctx).startsWith("OPRFV1-");
  }

  // --- withRandom ---

  @Test
  void withRandom_secureRandom_returnsNewInstanceWithSameProperties() {
    OprfCipherSuite original = OprfCipherSuite.builder().build();
    SecureRandom custom = new SecureRandom();
    OprfCipherSuite copy = original.withRandom(custom);

    assertThat(copy).isNotSameAs(original);
    assertThat(copy.identifier()).isEqualTo(original.identifier());
    assertThat(copy.hashAlgorithm()).isEqualTo(original.hashAlgorithm());
    assertThat(copy.randomConfig().random()).isSameAs(custom);
  }

  @Test
  void withRandom_randomProvider_returnsNewInstance() {
    OprfCipherSuite original = OprfCipherSuite.builder().build();
    RandomProvider rp = new RandomProvider();
    OprfCipherSuite copy = original.withRandom(rp);

    assertThat(copy).isNotSameAs(original);
    assertThat(copy.randomConfig()).isSameAs(rp);
  }

  // --- randomScalar ---

  @Test
  void randomScalar_isInRange() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    for (int i = 0; i < 10; i++) {
      BigInteger k = cs.randomScalar();
      assertThat(k).isGreaterThanOrEqualTo(BigInteger.ONE);
      assertThat(k).isLessThan(cs.groupSpec().groupOrder());
    }
  }

  // --- hash ---

  @Test
  void hash_sha256_producesCorrectLength() {
    OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build();
    byte[] result = cs.hash("test".getBytes(StandardCharsets.UTF_8));
    assertThat(result).hasSize(32);
  }

  @Test
  void hash_sha384_producesCorrectLength() {
    OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(CurveHashSuite.P384_SHA384).build();
    byte[] result = cs.hash("test".getBytes(StandardCharsets.UTF_8));
    assertThat(result).hasSize(48);
  }

  @Test
  void hash_sha512_producesCorrectLength() {
    OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(CurveHashSuite.P521_SHA512).build();
    byte[] result = cs.hash("test".getBytes(StandardCharsets.UTF_8));
    assertThat(result).hasSize(64);
  }

  @Test
  void hash_isDeterministic() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] input = "hello".getBytes(StandardCharsets.UTF_8);
    assertThat(cs.hash(input)).isEqualTo(cs.hash(input));
  }

  // --- hmac ---

  @Test
  void hmac_producesCorrectLength() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] key = new byte[32];
    byte[] data = "test".getBytes(StandardCharsets.UTF_8);
    byte[] result = cs.hmac(key, data);
    assertThat(result).hasSize(32);
  }

  @Test
  void hmac_isDeterministic() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] key = {1, 2, 3};
    byte[] data = {4, 5, 6};
    assertThat(cs.hmac(key, data)).isEqualTo(cs.hmac(key, data));
  }

  @Test
  void hmac_differentKeysDifferentOutput() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] data = "test".getBytes(StandardCharsets.UTF_8);
    byte[] mac1 = cs.hmac(new byte[]{1}, data);
    byte[] mac2 = cs.hmac(new byte[]{2}, data);
    assertThat(mac1).isNotEqualTo(mac2);
  }

  // --- hashToScalar ---

  @Test
  void hashToScalar_isInRange() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
    BigInteger s = cs.hashToScalar(msg, cs.hashToScalarDst());
    assertThat(s).isGreaterThanOrEqualTo(BigInteger.ZERO);
    assertThat(s).isLessThan(cs.groupSpec().groupOrder());
  }

  // --- deriveKeyPair ---

  @Test
  void deriveKeyPair_producesNonZeroScalar() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] seed = new byte[32];
    seed[0] = 1;
    BigInteger sk = cs.deriveKeyPair(seed, new byte[0]);
    assertThat(sk).isNotEqualTo(BigInteger.ZERO);
    assertThat(sk).isLessThan(cs.groupSpec().groupOrder());
  }

  @Test
  void deriveKeyPair_isDeterministic() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    byte[] seed = "seed-value-for-testing".getBytes(StandardCharsets.UTF_8);
    byte[] info = "info".getBytes(StandardCharsets.UTF_8);
    BigInteger sk1 = cs.deriveKeyPair(seed, info);
    BigInteger sk2 = cs.deriveKeyPair(seed, info);
    assertThat(sk1).isEqualTo(sk2);
  }

  @Test
  void deriveKeyPair_differentSeedsDifferentKeys() {
    OprfCipherSuite cs = OprfCipherSuite.builder().build();
    BigInteger sk1 = cs.deriveKeyPair("seed1".getBytes(StandardCharsets.UTF_8), new byte[0]);
    BigInteger sk2 = cs.deriveKeyPair("seed2".getBytes(StandardCharsets.UTF_8), new byte[0]);
    assertThat(sk1).isNotEqualTo(sk2);
  }

  // --- finalize ---

  @Nested
  class FinalizeTest {

    @Test
    void finalize_producesHashLengthOutput() {
      OprfCipherSuite cs = OprfCipherSuite.builder().build();
      // Create a valid blinded element: k * G
      BigInteger k = cs.randomScalar();
      byte[] element = cs.groupSpec().scalarMultiplyGenerator(k);
      byte[] input = "password".getBytes(StandardCharsets.UTF_8);
      BigInteger blind = cs.randomScalar();

      byte[] result = cs.finalize(input, blind, element);
      assertThat(result).hasSize(cs.hashOutputLength());
    }

    @Test
    void finalize_isDeterministic() {
      OprfCipherSuite cs = OprfCipherSuite.builder().build();
      BigInteger k = BigInteger.valueOf(42);
      byte[] element = cs.groupSpec().scalarMultiplyGenerator(k);
      byte[] input = "test".getBytes(StandardCharsets.UTF_8);
      BigInteger blind = BigInteger.valueOf(7);

      byte[] r1 = cs.finalize(input, blind, element);
      byte[] r2 = cs.finalize(input, blind, element);
      assertThat(r1).isEqualTo(r2);
    }

    /**
     * RFC 9497 §2.1: DeserializeElement MUST reject the identity element.
     *
     * <p>If a suite accepts it, {@code blindInv * O = O} and the OPRF output collapses to a
     * function of the input alone — independent of both the blind and the server key — so a
     * malicious server can silently downgrade the OPRF to an unkeyed hash. ristretto255 is the
     * suite that regressed: the all-zero encoding is a legitimate ristretto255 encoding, so the
     * RFC 9496 §4.3.1 decode checks pass for it and only this protocol-layer check catches it.
     * Mirrors the TypeScript regression in test/oprf.test.ts.
     *
     * <p>The identity encoding comes from {@link IdentityEncodings} rather than
     * {@code new byte[elementSize()]}, which this test used to build. That is not the identity
     * on the SEC1 suites — it is a malformed encoding, rejected earlier and for a different
     * reason — so with a permissive {@code isInstanceOfAny} assertion the P-256, P-384 and P-521
     * parameterizations passed without reaching the identity check at all.
     */
    @ParameterizedTest
    @EnumSource(CurveHashSuite.class)
    void finalize_identityEvaluatedElement_isRejected(CurveHashSuite suite) {
      OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
      byte[] identity = IdentityEncodings.identityFor(suite);
      byte[] input = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

      assertThatThrownBy(() -> cs.finalize(input, cs.randomScalar(), identity))
          .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    }

    /**
     * The identity must be rejected as an <em>identity</em>, not incidentally as a malformed
     * encoding. Without this, the suite above can silently regress back to covering one curve:
     * swapping in any unparseable buffer keeps it green, because both failures look alike
     * through {@code isInstanceOfAny}.
     *
     * <p>SEC1 {@code 0x00} is a structurally valid point encoding — one byte, the defined
     * encoding of the point at infinity — so reaching a rejection here means the decoder parsed
     * it and then refused it on its value.
     */
    @ParameterizedTest
    @EnumSource(CurveHashSuite.class)
    void finalize_identityIsRejectedOnItsValueNotItsLength(CurveHashSuite suite) {
      OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
      byte[] identity = IdentityEncodings.identityFor(suite);
      byte[] input = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

      assertThatThrownBy(() -> cs.finalize(input, cs.randomScalar(), identity))
          .as("the identity encoding for %s must be refused for being the identity, so the "
              + "message must name it rather than complain about the encoding's shape", suite)
          .hasMessageContaining("identity");
    }
  }

  @Nested
  class BlindValidation {

    /**
     * A blind congruent to 0 mod n inverts to 0, and 0 * anything is the identity — the same
     * key-independent collapse an identity evaluated element causes, reached from the
     * caller's side. Not hit by any in-tree path (randomScalar samples [1, n-1]), but
     * finalize() is public API.
     */
    @ParameterizedTest
    @EnumSource(CurveHashSuite.class)
    void finalize_zeroBlind_isRejected(CurveHashSuite suite) {
      OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
      byte[] element = cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(5));
      byte[] input = "test".getBytes(StandardCharsets.UTF_8);

      assertThatThrownBy(() -> cs.finalize(input, BigInteger.ZERO, element))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("non-zero scalar");
    }

    /** The group order itself is congruent to zero and must be rejected the same way. */
    @ParameterizedTest
    @EnumSource(CurveHashSuite.class)
    void finalize_blindEqualToGroupOrder_isRejected(CurveHashSuite suite) {
      OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
      byte[] element = cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(5));
      byte[] input = "test".getBytes(StandardCharsets.UTF_8);

      assertThatThrownBy(() -> cs.finalize(input, cs.groupSpec().groupOrder(), element))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("non-zero scalar");
    }

    @ParameterizedTest
    @EnumSource(CurveHashSuite.class)
    void finalize_validBlind_stillWorks(CurveHashSuite suite) {
      OprfCipherSuite cs = OprfCipherSuite.builder().withSuite(suite).build();
      byte[] element = cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(5));
      byte[] input = "test".getBytes(StandardCharsets.UTF_8);

      assertThat(cs.finalize(input, cs.randomScalar(), element))
          .hasSize(cs.hashOutputLength());
    }
  }

  @Nested
  class IdentityElementRejection {

    @Test
    void ristretto255_decodeIdentity_isRejected() {
      OprfCipherSuite cs =
          OprfCipherSuite.builder().withSuite(CurveHashSuite.RISTRETTO255_SHA512).build();

      assertThatThrownBy(() -> cs.groupSpec().scalarMultiply(BigInteger.TWO, new byte[32]))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("identity");
    }

    @Test
    void ristretto255_nonIdentityElement_stillDecodes() {
      OprfCipherSuite cs =
          OprfCipherSuite.builder().withSuite(CurveHashSuite.RISTRETTO255_SHA512).build();
      byte[] generator = cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(9));

      assertThat(cs.groupSpec().scalarMultiply(BigInteger.TWO, generator)).hasSize(32);
    }
  }
}
