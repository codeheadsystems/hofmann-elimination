package com.codeheadsystems.hofmann.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test suite for RFC 9380 hash-to-curve implementation.
 * <p>
 * Includes test vectors from RFC 9380 Appendix J.7.1 for secp256k1_XMD:SHA-256_SSWU_RO_.
 */
public class HashToCurveTest {

  private static final String DST = "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
  private HashToCurve hashToCurve;

  @BeforeEach
  void setUp() {
    hashToCurve = HashToCurve.forSecp256k1(Curve.DEFAULT_CURVE);
  }

  @Test
  void testHashToCurveEmptyString() {
    // Test vector from RFC 9380 Appendix J.7.1
    // msg = ""
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
        16
    );
    BigInteger expectedY = new BigInteger(
        "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveABC() {
    // Test vector from RFC 9380 Appendix J.7.1
    // msg = "abc"
    byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
        16
    );
    BigInteger expectedY = new BigInteger(
        "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveAbcdef() {
    // Test vector from RFC 9380 Appendix J.7.1
    // msg = "abcdef0123456789"
    byte[] msg = "abcdef0123456789".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380 Appendix J.8.1
    BigInteger expectedX = new BigInteger(
        "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
        16
    );
    BigInteger expectedY = new BigInteger(
        "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveLongMessage() {
    // Test vector from RFC 9380 Appendix J.7.1
    // msg = "q128_" + "q" * 128
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) {
      sb.append("q");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
        16
    );
    BigInteger expectedY = new BigInteger(
        "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveA512Times() {
    // Test vector from RFC 9380 Appendix J.7.1
    // msg = "a512_" + "a" * 512
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) {
      sb.append("a");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // Expected values from RFC 9380
    BigInteger expectedX = new BigInteger(
        "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
        16
    );
    BigInteger expectedY = new BigInteger(
        "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveResultIsOnCurve() {
    // Verify that the result is actually on the secp256k1 curve
    byte[] msg = "test message".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST).normalize();

    // Check that the point satisfies the curve equation: y^2 = x^3 + 7
    BigInteger x = point.getXCoord().toBigInteger();
    BigInteger y = point.getYCoord().toBigInteger();
    BigInteger p = Curve.DEFAULT_CURVE.getCurve().getField().getCharacteristic();

    System.out.println("On-curve test: x = " + x.toString(16));
    System.out.println("On-curve test: y = " + y.toString(16));

    BigInteger lhs = y.modPow(BigInteger.TWO, p);
    BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
        .add(BigInteger.valueOf(7))
        .mod(p);

    System.out.println("y^2 mod p = " + lhs.toString(16));
    System.out.println("x^3+7 mod p = " + rhs.toString(16));

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
