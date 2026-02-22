package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test suite for RFC 9380 hash-to-curve implementation for P-256.
 * <p>
 * Includes test vectors from RFC 9380 Appendix J.2.1 for P256_XMD:SHA-256_SSWU_RO_.
 */
public class P256HashToCurveTest {

  private static final String DST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
  private HashToCurve hashToCurve;

  @BeforeEach
  void setUp() {
    hashToCurve = HashToCurve.forP256();
  }

  @Test
  void testHashToCurveEmptyString() {
    // Test vector from RFC 9380 Appendix J.2.1
    // msg = ""
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
        16
    );
    BigInteger expectedY = new BigInteger(
        "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveABC() {
    // Test vector from RFC 9380 Appendix J.2.1
    // msg = "abc"
    byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
        16
    );
    BigInteger expectedY = new BigInteger(
        "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveAbcdef() {
    // Test vector from RFC 9380 Appendix J.2.1
    // msg = "abcdef0123456789"
    byte[] msg = "abcdef0123456789".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
        16
    );
    BigInteger expectedY = new BigInteger(
        "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveLongMessage() {
    // Test vector from RFC 9380 Appendix J.2.1
    // msg = "q128_" + "q" * 128
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) {
      sb.append("q");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
        16
    );
    BigInteger expectedY = new BigInteger(
        "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveA512Times() {
    // Test vector from RFC 9380 Appendix J.2.1
    // msg = "a512_" + "a" * 512
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) {
      sb.append("a");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
        16
    );
    BigInteger expectedY = new BigInteger(
        "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveResultIsOnCurve() {
    // Verify that the result is actually on the P-256 curve
    byte[] msg = "test message".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST).normalize();

    // Check that the point satisfies the curve equation: y^2 = x^3 - 3x + b
    BigInteger x = point.getXCoord().toBigInteger();
    BigInteger y = point.getYCoord().toBigInteger();
    BigInteger p = Curve.P256_CURVE.params().getCurve().getField().getCharacteristic();
    BigInteger b = Curve.P256_CURVE.params().getCurve().getB().toBigInteger();

    System.out.println("P-256 On-curve test: x = " + x.toString(16));
    System.out.println("P-256 On-curve test: y = " + y.toString(16));

    BigInteger lhs = y.modPow(BigInteger.TWO, p);
    BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
        .subtract(x.multiply(BigInteger.valueOf(3)))
        .add(b)
        .mod(p);

    System.out.println("y^2 mod p = " + lhs.toString(16));
    System.out.println("x^3-3x+b mod p = " + rhs.toString(16));

    assertThat(lhs).isEqualTo(rhs);
  }

  @Test
  void testDeterministicOutput() {
    // Same input should always produce the same output
    byte[] msg = "deterministic test".getBytes(StandardCharsets.UTF_8);

    ECPoint point1 = hashToCurve.hashToCurve(msg, DST);
    ECPoint point2 = hashToCurve.hashToCurve(msg, DST);

    assertThat(point1.getXCoord().toBigInteger())
        .isEqualTo(point2.getXCoord().toBigInteger());
    assertThat(point1.getYCoord().toBigInteger())
        .isEqualTo(point2.getYCoord().toBigInteger());
  }

  @Test
  void testDifferentMessagesProduceDifferentPoints() {
    // Different inputs should produce different outputs
    byte[] msg1 = "message1".getBytes(StandardCharsets.UTF_8);
    byte[] msg2 = "message2".getBytes(StandardCharsets.UTF_8);

    ECPoint point1 = hashToCurve.hashToCurve(msg1, DST);
    ECPoint point2 = hashToCurve.hashToCurve(msg2, DST);

    assertThat(point1.getXCoord().toBigInteger())
        .isNotEqualTo(point2.getXCoord().toBigInteger());
  }

  @Test
  void testDomainSeparationWorks() {
    // Same message with different DST should produce different outputs
    byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
    String dst1 = "DST-1";
    String dst2 = "DST-2";

    ECPoint point1 = hashToCurve.hashToCurve(msg, dst1);
    ECPoint point2 = hashToCurve.hashToCurve(msg, dst2);

    assertThat(point1.getXCoord().toBigInteger())
        .isNotEqualTo(point2.getXCoord().toBigInteger());
  }
}
