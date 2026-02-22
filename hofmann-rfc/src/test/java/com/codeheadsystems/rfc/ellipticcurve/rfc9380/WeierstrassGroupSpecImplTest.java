package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class WeierstrassGroupSpecImplTest {

  // --- Factory / static constant tests ---

  @Test
  void p256Sha256_returnsP256Curve() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    assertThat(spec.curve()).isEqualTo(Curve.P256_CURVE);
  }

  @Test
  void p384Sha384_returnsP384Curve() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P384_SHA384;
    assertThat(spec.curve()).isEqualTo(Curve.P384_CURVE);
  }

  @Test
  void p521Sha512_returnsP521Curve() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P521_SHA512;
    assertThat(spec.curve()).isEqualTo(Curve.P521_CURVE);
  }

  @Test
  void forSecp256k1_returnsSecp256k1Curve() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.forSecp256k1();
    assertThat(spec.curve()).isEqualTo(Curve.SECP256K1_CURVE);
  }

  // --- groupOrder ---

  static Stream<Arguments> groupOrderArgs() {
    return Stream.of(
        Arguments.of(WeierstrassGroupSpecImpl.P256_SHA256, Curve.P256_CURVE.n()),
        Arguments.of(WeierstrassGroupSpecImpl.P384_SHA384, Curve.P384_CURVE.n()),
        Arguments.of(WeierstrassGroupSpecImpl.P521_SHA512, Curve.P521_CURVE.n())
    );
  }

  @ParameterizedTest
  @MethodSource("groupOrderArgs")
  void groupOrder_matchesCurveOrder(WeierstrassGroupSpecImpl spec, BigInteger expectedOrder) {
    assertThat(spec.groupOrder()).isEqualTo(expectedOrder);
  }

  // --- elementSize ---

  static Stream<Arguments> elementSizeArgs() {
    return Stream.of(
        Arguments.of(WeierstrassGroupSpecImpl.P256_SHA256, 33),   // 1 + 32
        Arguments.of(WeierstrassGroupSpecImpl.P384_SHA384, 49),   // 1 + 48
        Arguments.of(WeierstrassGroupSpecImpl.P521_SHA512, 67)    // 1 + 66
    );
  }

  @ParameterizedTest
  @MethodSource("elementSizeArgs")
  void elementSize_isCompressedSec1Size(WeierstrassGroupSpecImpl spec, int expectedSize) {
    assertThat(spec.elementSize()).isEqualTo(expectedSize);
  }

  // --- hashToGroup ---

  @Test
  void hashToGroup_returnsCompressedPointOfCorrectLength() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    byte[] dst = "test-dst".getBytes(StandardCharsets.UTF_8);
    byte[] result = spec.hashToGroup("hello".getBytes(StandardCharsets.UTF_8), dst);
    assertThat(result).hasSize(spec.elementSize());
    // First byte of compressed SEC1 is 0x02 or 0x03
    assertThat(result[0]).isIn((byte) 0x02, (byte) 0x03);
  }

  // --- hashToScalar ---

  @Test
  void hashToScalar_returnsValueInRange() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    byte[] dst = "test-dst".getBytes(StandardCharsets.UTF_8);
    BigInteger scalar = spec.hashToScalar("hello".getBytes(StandardCharsets.UTF_8), dst);
    assertThat(scalar).isGreaterThanOrEqualTo(BigInteger.ZERO);
    assertThat(scalar).isLessThan(spec.groupOrder());
  }

  // --- scalarMultiplyGenerator / scalarMultiply ---

  @Test
  void scalarMultiplyGenerator_returnsValidCompressedPoint() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    byte[] result = spec.scalarMultiplyGenerator(BigInteger.valueOf(42));
    assertThat(result).hasSize(spec.elementSize());
    assertThat(result[0]).isIn((byte) 0x02, (byte) 0x03);
  }

  @Test
  void scalarMultiply_generatorTimesK_matchesScalarMultiplyGenerator() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    BigInteger k = BigInteger.valueOf(12345);
    byte[] viaGenerator = spec.scalarMultiplyGenerator(k);
    // Serialize the generator, then scalarMultiply
    byte[] generatorBytes = spec.curve().g().normalize().getEncoded(true);
    byte[] viaMultiply = spec.scalarMultiply(k, generatorBytes);
    assertThat(viaMultiply).isEqualTo(viaGenerator);
  }

  // --- serializeScalar ---

  @Nested
  class SerializeScalarTest {

    private final WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    private final int scalarSize = (spec.groupOrder().bitLength() + 7) / 8; // 32 for P-256

    @Test
    void zero_producesAllZeroBytes() {
      byte[] result = spec.serializeScalar(BigInteger.ZERO);
      assertThat(result).hasSize(scalarSize);
      assertThat(result).isEqualTo(new byte[scalarSize]);
    }

    @Test
    void one_producesLeadingZeroPaddedBytes() {
      byte[] result = spec.serializeScalar(BigInteger.ONE);
      assertThat(result).hasSize(scalarSize);
      assertThat(result[scalarSize - 1]).isEqualTo((byte) 1);
      // All leading bytes are zero
      for (int i = 0; i < scalarSize - 1; i++) {
        assertThat(result[i]).as("byte[%d]", i).isZero();
      }
    }

    @Test
    void nMinusOne_isMaxValidScalar() {
      BigInteger nMinusOne = spec.groupOrder().subtract(BigInteger.ONE);
      byte[] result = spec.serializeScalar(nMinusOne);
      assertThat(result).hasSize(scalarSize);
      // Deserialize back
      BigInteger recovered = new BigInteger(1, result);
      assertThat(recovered).isEqualTo(nMinusOne);
    }

    @Test
    void valueWithLeadingSignByte_isStripped() {
      // Pick a value whose BigInteger.toByteArray() produces a leading 0x00 sign byte.
      // A value with bit 255 set (for P-256, 32-byte scalar) will have 33-byte toByteArray().
      BigInteger val = BigInteger.ONE.shiftLeft(255); // 2^255
      // Ensure it's in range
      assertThat(val).isLessThan(spec.groupOrder());
      byte[] result = spec.serializeScalar(val);
      assertThat(result).hasSize(scalarSize);
      assertThat(result[0]).isEqualTo((byte) 0x80);
    }

    @Test
    void smallValue_isPaddedToFullLength() {
      BigInteger small = BigInteger.valueOf(0xFF);
      byte[] result = spec.serializeScalar(small);
      assertThat(result).hasSize(scalarSize);
      BigInteger recovered = new BigInteger(1, result);
      assertThat(recovered).isEqualTo(small);
    }

    @Test
    void negativeScalar_throwsIllegalArgument() {
      assertThatThrownBy(() -> spec.serializeScalar(BigInteger.valueOf(-1)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("out of range");
    }

    @Test
    void scalarEqualToN_throwsIllegalArgument() {
      assertThatThrownBy(() -> spec.serializeScalar(spec.groupOrder()))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("out of range");
    }

    @Test
    void scalarGreaterThanN_throwsIllegalArgument() {
      assertThatThrownBy(() -> spec.serializeScalar(spec.groupOrder().add(BigInteger.ONE)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("out of range");
    }

    @Test
    void roundTrip_allSuites() {
      for (WeierstrassGroupSpecImpl s : new WeierstrassGroupSpecImpl[]{
          WeierstrassGroupSpecImpl.P256_SHA256,
          WeierstrassGroupSpecImpl.P384_SHA384,
          WeierstrassGroupSpecImpl.P521_SHA512}) {
        BigInteger val = s.groupOrder().subtract(BigInteger.TWO);
        byte[] serialized = s.serializeScalar(val);
        int ns = (s.groupOrder().bitLength() + 7) / 8;
        assertThat(serialized).hasSize(ns);
        BigInteger recovered = new BigInteger(1, serialized);
        assertThat(recovered).as("round-trip for %s", s.curve()).isEqualTo(val);
      }
    }
  }

  // --- deserializePoint ---

  @Nested
  class DeserializePointTest {

    private final WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;

    @Test
    void validCompressedPoint_succeeds() {
      // Serialize the generator and deserialize it back
      byte[] encoded = spec.curve().g().normalize().getEncoded(true);
      ECPoint result = spec.deserializePoint(encoded);
      assertThat(result.normalize().getXCoord().toBigInteger())
          .isEqualTo(spec.curve().g().normalize().getXCoord().toBigInteger());
    }

    @Test
    void identityPoint_throwsSecurityException() {
      // The identity (point at infinity) in SEC1 compressed encoding is a single 0x00 byte
      byte[] infinity = new byte[]{0x00};
      assertThatThrownBy(() -> spec.deserializePoint(infinity))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("identity");
    }

    @Test
    void invalidPoint_throwsSecurityException() {
      // Take a valid compressed point and corrupt the x-coordinate so it's off-curve.
      // Use a compressed encoding with a valid prefix but garbage x-coordinate.
      byte[] bad = new byte[spec.elementSize()];
      bad[0] = 0x02; // valid compressed prefix
      // Fill with 0xFF — almost certainly not on the curve
      for (int i = 1; i < bad.length; i++) {
        bad[i] = (byte) 0xFF;
      }
      // BouncyCastle may throw IllegalArgumentException for invalid points during decodePoint
      assertThatThrownBy(() -> spec.deserializePoint(bad))
          .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    }

    @Test
    void scalarMultiply_withDeserializedPoint_roundTrips() {
      byte[] gen = spec.curve().g().normalize().getEncoded(true);
      BigInteger k = BigInteger.valueOf(7);
      byte[] kG = spec.scalarMultiply(k, gen);
      // Deserialize the result — should be valid
      ECPoint p = spec.deserializePoint(kG);
      assertThat(p.isInfinity()).isFalse();
      assertThat(p.isValid()).isTrue();
    }
  }
}
