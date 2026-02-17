package com.codeheadsystems.oprf.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.oprf.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test suite for RFC 9380 hash-to-curve implementation for P-384.
 * <p>
 * Includes test vectors from RFC 9380 Appendix J.3.1 for P384_XMD:SHA-384_SSWU_RO_.
 */
public class P384HashToCurveTest {

  private static final String DST = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_";
  private HashToCurve hashToCurve;

  @BeforeEach
  void setUp() {
    hashToCurve = HashToCurve.forP384();
  }

  @Test
  void testHashToCurveEmptyString() {
    // Test vector from RFC 9380 Appendix J.3.1
    // msg = ""
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83",
        16
    );
    BigInteger expectedY = new BigInteger(
        "0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveABC() {
    // Test vector from RFC 9380 Appendix J.3.1
    // msg = "abc"
    byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1",
        16
    );
    BigInteger expectedY = new BigInteger(
        "01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveAbcdef() {
    // Test vector from RFC 9380 Appendix J.3.1
    // msg = "abcdef0123456789"
    byte[] msg = "abcdef0123456789".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "bdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a5d6b78676400926fbceee6fcd1780fe86e62b2aa89",
        16
    );
    BigInteger expectedY = new BigInteger(
        "57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e0f47e46e4e4b85a0595da29c9494c1814acafe183c",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveLongMessage() {
    // Test vector from RFC 9380 Appendix J.3.1
    // msg = "q128_" + "q" * 128
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) {
      sb.append("q");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "03c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a3850e0456f5dd7f7633dd31676d990eda32882ab486c0",
        16
    );
    BigInteger expectedY = new BigInteger(
        "cc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5ea662482b8c1f43dc453a93b94a8026db58f3f5d878",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveA512Times() {
    // Test vector from RFC 9380 Appendix J.3.1
    // msg = "a512_" + "a" * 512
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) {
      sb.append("a");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c5604325f1cdea4c15c10a54ef303aabf2ea58bd9947a4",
        16
    );
    BigInteger expectedY = new BigInteger(
        "ea857285a33abb516732915c353c75c576bf82ccc96adb63c094dde580021eddeafd91f8c0bfee6f636528f3d0c47fd2",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveResultIsOnCurve() {
    // Verify that the result is actually on the P-384 curve: y^2 = x^3 - 3x + b
    byte[] msg = "test message".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST).normalize();

    BigInteger x = point.getXCoord().toBigInteger();
    BigInteger y = point.getYCoord().toBigInteger();
    BigInteger p = Curve.P384_CURVE.params().getCurve().getField().getCharacteristic();
    BigInteger b = Curve.P384_CURVE.params().getCurve().getB().toBigInteger();

    BigInteger lhs = y.modPow(BigInteger.TWO, p);
    BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
        .subtract(x.multiply(BigInteger.valueOf(3)))
        .add(b)
        .mod(p);

    assertThat(lhs).isEqualTo(rhs);
  }
}
