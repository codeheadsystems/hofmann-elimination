package com.codeheadsystems.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * Pipeline-stage tests for RFC 9380 hash-to-curve on P-384.
 * Uses intermediate test vectors from RFC 9380 Appendix J.3.1 (msg = "").
 *
 * <p>Stages: hash_to_field → SimplifiedSWU → point addition → full pipeline.
 * Unlike secp256k1 there is no isogeny step; SWU maps directly onto P-384.
 */
public class P384ComponentTest {

  private static final byte[] DST =
      "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_".getBytes(StandardCharsets.UTF_8);

  // RFC 9380 J.3.1, msg = "" — hash_to_field outputs
  private static final BigInteger EXPECTED_U0 = new BigInteger(
      "25c8d7dc1acd4ee617766693f7f8829396065d1b447eedb155871feffd9c6653279ac7e5c46edb7010a0e4ff64c9f3b4",
      16);
  private static final BigInteger EXPECTED_U1 = new BigInteger(
      "59428be4ed69131df59a0c6a8e188d2d4ece3f1b2a3a02602962b47efa4d7905945b1e2cc80b36aa35c99451073521ac",
      16);

  // Q0 = map_to_curve(u0) — SWU output directly on P-384 (no isogeny)
  private static final BigInteger EXPECTED_Q0_X = new BigInteger(
      "e4717e29eef38d862bee4902a7d21b44efb58c464e3e1f0d03894d94de310f8ffc6de86786dd3e15a1541b18d4eb2846",
      16);
  private static final BigInteger EXPECTED_Q0_Y = new BigInteger(
      "6b95a6e639822312298a47526bb77d9cd7bcf76244c991c8cd70075e2ee6e8b9a135c4a37e3c0768c7ca871c0ceb53d4",
      16);

  // Q1 = map_to_curve(u1)
  private static final BigInteger EXPECTED_Q1_X = new BigInteger(
      "509527cfc0750eedc53147e6d5f78596c8a3b7360e0608e2fab0563a1670d58d8ae107c9f04bcf90e89489ace5650efd",
      16);
  private static final BigInteger EXPECTED_Q1_Y = new BigInteger(
      "33337b13cb35e173fdea4cb9e8cce915d836ff57803dbbeb7998aa49d17df2ff09b67031773039d09fbd9305a1566bc4",
      16);

  // P = Q0 + Q1 — final point (matches P384HashToCurveTest.testHashToCurveEmptyString)
  private static final BigInteger EXPECTED_P_X = new BigInteger(
      "eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83",
      16);
  private static final BigInteger EXPECTED_P_Y = new BigInteger(
      "0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a",
      16);

  @Test
  void stage1_hashToField() {
    HashToField h2f = HashToField.forP384();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    BigInteger[] u = h2f.hashToField(msg, DST, 2);

    assertThat(u[0]).as("u[0]").isEqualTo(EXPECTED_U0);
    assertThat(u[1]).as("u[1]").isEqualTo(EXPECTED_U1);
  }

  @Test
  void stage2_simplifiedSWU() {
    SimplifiedSWU swu = SimplifiedSWU.forP384();

    BigInteger[] swu0 = swu.map(EXPECTED_U0);
    BigInteger[] swu1 = swu.map(EXPECTED_U1);

    assertThat(swu0[0]).as("Q0.x").isEqualTo(EXPECTED_Q0_X);
    assertThat(swu0[1]).as("Q0.y").isEqualTo(EXPECTED_Q0_Y);
    assertThat(swu1[0]).as("Q1.x").isEqualTo(EXPECTED_Q1_X);
    assertThat(swu1[1]).as("Q1.y").isEqualTo(EXPECTED_Q1_Y);

    // Verify points lie on P-384: y² = x³ - 3x + b
    BigInteger p = Curve.P384_CURVE.params().getCurve().getField().getCharacteristic();
    BigInteger b = Curve.P384_CURVE.params().getCurve().getB().toBigInteger();

    for (BigInteger[] q : new BigInteger[][]{swu0, swu1}) {
      BigInteger lhs = q[1].modPow(BigInteger.TWO, p);
      BigInteger rhs = q[0].modPow(BigInteger.valueOf(3), p)
          .subtract(q[0].multiply(BigInteger.valueOf(3)))
          .add(b)
          .mod(p);
      assertThat(lhs).as("point on P-384").isEqualTo(rhs);
    }
  }

  @Test
  void stage3_pointAddition() {
    ECPoint Q0 = Curve.P384_CURVE.params().getCurve()
        .createPoint(EXPECTED_Q0_X, EXPECTED_Q0_Y);
    ECPoint Q1 = Curve.P384_CURVE.params().getCurve()
        .createPoint(EXPECTED_Q1_X, EXPECTED_Q1_Y);

    ECPoint P = Q0.add(Q1).normalize();

    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }

  @Test
  void stage4_fullPipeline() {
    HashToCurve h2c = HashToCurve.forP384();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint P = h2c.hashToCurve(msg, DST);

    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }
}
