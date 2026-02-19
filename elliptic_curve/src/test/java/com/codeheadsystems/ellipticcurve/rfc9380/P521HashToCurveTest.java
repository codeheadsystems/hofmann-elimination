package com.codeheadsystems.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test suite for RFC 9380 hash-to-curve implementation for P-521.
 * <p>
 * Includes test vectors from RFC 9380 Appendix J.4.1 for P521_XMD:SHA-512_SSWU_RO_.
 */
public class P521HashToCurveTest {

  private static final String DST = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_";
  private HashToCurve hashToCurve;

  @BeforeEach
  void setUp() {
    hashToCurve = HashToCurve.forP521();
  }

  @Test
  void testHashToCurveEmptyString() {
    // Test vector from RFC 9380 Appendix J.4.1
    // msg = ""
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    // P-521 coordinates are 66 bytes (leading zero-padded)
    BigInteger expectedX = new BigInteger(
        "00fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef3556ed9f7f1bc23cecc9c088",
        16
    );
    BigInteger expectedY = new BigInteger(
        "0169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c27166dc3fe5eeef782be411d",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveABC() {
    // Test vector from RFC 9380 Appendix J.4.1
    // msg = "abc"
    byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "002f89a1677b28054b50d15e1f81ed6669b5a2158211118ebdef8a6efc77f8ccaa528f698214e4340155abc1fa08f8f613ef14a043717503d57e267d57155cf784a4",
        16
    );
    BigInteger expectedY = new BigInteger(
        "010e0be5dc8e753da8ce51091908b72396d3deed14ae166f66d8ebf0a4e7059ead169ea4bead0232e9b700dd380b316e9361cfdba55a08c73545563a80966ecbb86d",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveAbcdef() {
    // Test vector from RFC 9380 Appendix J.4.1
    // msg = "abcdef0123456789"
    byte[] msg = "abcdef0123456789".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "006e200e276a4a81760099677814d7f8794a4a5f3658442de63c18d2244dcc957c645e94cb0754f95fcf103b2aeaf94411847c24187b89fb7462ad3679066337cbc4",
        16
    );
    BigInteger expectedY = new BigInteger(
        "001dd8dfa9775b60b1614f6f169089d8140d4b3e4012949b52f98db2deff3e1d97bf73a1fa4d437d1dcdf39b6360cc518d8ebcc0f899018206fded7617b654f6b168",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveLongMessage() {
    // Test vector from RFC 9380 Appendix J.4.1
    // msg = "q128_" + "q" * 128
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) {
      sb.append("q");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "01b264a630bd6555be537b000b99a06761a9325c53322b65bdc41bf196711f9708d58d34b3b90faf12640c27b91c70a507998e55940648caa8e71098bf2bc8d24664",
        16
    );
    BigInteger expectedY = new BigInteger(
        "01ea9f445bee198b3ee4c812dcf7b0f91e0881f0251aab272a12201fd89b1a95733fd2a699c162b639e9acdcc54fdc2f6536129b6beb0432be01aa8da02df5e59aaa",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveA512Times() {
    // Test vector from RFC 9380 Appendix J.4.1
    // msg = "a512_" + "a" * 512
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) {
      sb.append("a");
    }
    byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST);

    BigInteger expectedX = new BigInteger(
        "00c12bc3e28db07b6b4d2a2b1167ab9e26fc2fa85c7b0498a17b0347edf52392856d7e28b8fa7a2dd004611159505835b687ecf1a764857e27e9745848c436ef3925",
        16
    );
    BigInteger expectedY = new BigInteger(
        "01cd287df9a50c22a9231beb452346720bb163344a41c5f5a24e8335b6ccc595fd436aea89737b1281aecb411eb835f0b939073fdd1dd4d5a2492e91ef4a3c55bcbd",
        16
    );

    assertThat(point.getXCoord().toBigInteger()).isEqualTo(expectedX);
    assertThat(point.getYCoord().toBigInteger()).isEqualTo(expectedY);
  }

  @Test
  void testHashToCurveResultIsOnCurve() {
    // Verify that the result is actually on the P-521 curve: y^2 = x^3 - 3x + b
    byte[] msg = "test message".getBytes(StandardCharsets.UTF_8);

    ECPoint point = hashToCurve.hashToCurve(msg, DST).normalize();

    BigInteger x = point.getXCoord().toBigInteger();
    BigInteger y = point.getYCoord().toBigInteger();
    BigInteger p = Curve.P521_CURVE.params().getCurve().getField().getCharacteristic();
    BigInteger b = Curve.P521_CURVE.params().getCurve().getB().toBigInteger();

    BigInteger lhs = y.modPow(BigInteger.TWO, p);
    BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
        .subtract(x.multiply(BigInteger.valueOf(3)))
        .add(b)
        .mod(p);

    assertThat(lhs).isEqualTo(rhs);
  }
}
