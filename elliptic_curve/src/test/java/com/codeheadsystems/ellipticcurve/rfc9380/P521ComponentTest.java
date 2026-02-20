package com.codeheadsystems.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * Pipeline-stage tests for RFC 9380 hash-to-curve on P-521.
 * Uses intermediate test vectors from RFC 9380 Appendix J.4.1 (msg = "").
 *
 * <p>Stages: hash_to_field → SimplifiedSWU → point addition → full pipeline.
 * Unlike secp256k1 there is no isogeny step; SWU maps directly onto P-521.
 */
public class P521ComponentTest {

  private static final byte[] DST =
      "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_".getBytes(StandardCharsets.UTF_8);

  // RFC 9380 J.4.1, msg = "" — hash_to_field outputs
  private static final BigInteger EXPECTED_U0 = new BigInteger(
      "01e5f09974e5724f25286763f00ce76238c7a6e03dc396600350ee2c4135fb17dc555be99a4a4bae0fd303d4f66d984ed7b6a3ba386093752a855d26d559d69e7e9e",
      16);
  private static final BigInteger EXPECTED_U1 = new BigInteger(
      "00ae593b42ca2ef93ac488e9e09a5fe5a2f6fb330d18913734ff602f2a761fcaaf5f596e790bcc572c9140ec03f6cccc38f767f1c1975a0b4d70b392d95a0c7278aa",
      16);

  // Q0 = map_to_curve(u0) — SWU output directly on P-521 (no isogeny)
  private static final BigInteger EXPECTED_Q0_X = new BigInteger(
      "00b70ae99b6339fffac19cb9bfde2098b84f75e50ac1e80d6acb954e4534af5f0e9c4a5b8a9c10317b8e6421574bae2b133b4f2b8c6ce4b3063da1d91d34fa2b3a3c",
      16);
  private static final BigInteger EXPECTED_Q0_Y = new BigInteger(
      "007f368d98a4ddbf381fb354de40e44b19e43bb11a1278759f4ea7b485e1b6db33e750507c071250e3e443c1aaed61f2c28541bb54b1b456843eda1eb15ec2a9b36e",
      16);

  // Q1 = map_to_curve(u1)
  private static final BigInteger EXPECTED_Q1_X = new BigInteger(
      "01143d0e9cddcdacd6a9aafe1bcf8d218c0afc45d4451239e821f5d2a56df92be942660b532b2aa59a9c635ae6b30e803c45a6ac871432452e685d661cd41cf67214",
      16);
  private static final BigInteger EXPECTED_Q1_Y = new BigInteger(
      "00ff75515df265e996d702a5380defffab1a6d2bc232234c7bcffa433cd8aa791fbc8dcf667f08818bffa739ae25773b32073213cae9a0f2a917a0b1301a242dda0c",
      16);

  // P = Q0 + Q1 — final point (matches P521HashToCurveTest.testHashToCurveEmptyString)
  private static final BigInteger EXPECTED_P_X = new BigInteger(
      "00fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef3556ed9f7f1bc23cecc9c088",
      16);
  private static final BigInteger EXPECTED_P_Y = new BigInteger(
      "0169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c27166dc3fe5eeef782be411d",
      16);

  @Test
  void stage1_hashToField() {
    HashToField h2f = HashToField.forP521();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    BigInteger[] u = h2f.hashToField(msg, DST, 2);

    assertThat(u[0]).as("u[0]").isEqualTo(EXPECTED_U0);
    assertThat(u[1]).as("u[1]").isEqualTo(EXPECTED_U1);
  }

  @Test
  void stage2_simplifiedSWU() {
    SimplifiedSWU swu = SimplifiedSWU.forP521();

    BigInteger[] swu0 = swu.map(EXPECTED_U0);
    BigInteger[] swu1 = swu.map(EXPECTED_U1);

    assertThat(swu0[0]).as("Q0.x").isEqualTo(EXPECTED_Q0_X);
    assertThat(swu0[1]).as("Q0.y").isEqualTo(EXPECTED_Q0_Y);
    assertThat(swu1[0]).as("Q1.x").isEqualTo(EXPECTED_Q1_X);
    assertThat(swu1[1]).as("Q1.y").isEqualTo(EXPECTED_Q1_Y);

    // Verify points lie on P-521: y² = x³ - 3x + b
    BigInteger p = Curve.P521_CURVE.params().getCurve().getField().getCharacteristic();
    BigInteger b = Curve.P521_CURVE.params().getCurve().getB().toBigInteger();

    for (BigInteger[] q : new BigInteger[][]{swu0, swu1}) {
      BigInteger lhs = q[1].modPow(BigInteger.TWO, p);
      BigInteger rhs = q[0].modPow(BigInteger.valueOf(3), p)
          .subtract(q[0].multiply(BigInteger.valueOf(3)))
          .add(b)
          .mod(p);
      assertThat(lhs).as("point on P-521").isEqualTo(rhs);
    }
  }

  @Test
  void stage3_pointAddition() {
    ECPoint Q0 = Curve.P521_CURVE.params().getCurve()
        .createPoint(EXPECTED_Q0_X, EXPECTED_Q0_Y);
    ECPoint Q1 = Curve.P521_CURVE.params().getCurve()
        .createPoint(EXPECTED_Q1_X, EXPECTED_Q1_Y);

    ECPoint P = Q0.add(Q1).normalize();

    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }

  @Test
  void stage4_fullPipeline() {
    HashToCurve h2c = HashToCurve.forP521();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint P = h2c.hashToCurve(msg, DST);

    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }
}
