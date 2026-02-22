package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * Debug tests to verify each stage of the RFC 9380 hash-to-curve pipeline for P-256.
 * Uses intermediate test vectors from RFC 9380 Appendix J.2.1.
 */
public class P256ComponentTest {
  private static final byte[] DST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.UTF_8);
  // Test vector 1: msg = "" (empty string) from RFC 9380 Appendix J.2.1
  private static final BigInteger EXPECTED_U0 = new BigInteger("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009", 16);
  private static final BigInteger EXPECTED_U1 = new BigInteger("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a", 16);
  // Q0 and Q1 are after SWU (on P-256, no isogeny needed)
  private static final BigInteger EXPECTED_Q0_X = new BigInteger("ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5", 16);
  private static final BigInteger EXPECTED_Q0_Y = new BigInteger("dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1", 16);
  private static final BigInteger EXPECTED_Q1_X = new BigInteger("51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5", 16);
  private static final BigInteger EXPECTED_Q1_Y = new BigInteger("b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac", 16);
  // Final point P = Q0 + Q1
  private static final BigInteger EXPECTED_P_X = new BigInteger("2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4", 16);
  private static final BigInteger EXPECTED_P_Y = new BigInteger("8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415", 16);

  /**
   * Stage 1 hash to field.
   */
  @Test
  void stage1_hashToField() {
    HashToField h2f = HashToField.forP256();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);
    BigInteger[] u = h2f.hashToField(msg, DST, 2);
    System.out.println("=== Stage 1: hash_to_field (P-256) ===");
    System.out.println("u[0] expected: " + EXPECTED_U0.toString(16));
    System.out.println("u[0] actual:   " + u[0].toString(16));
    System.out.println("u[1] expected: " + EXPECTED_U1.toString(16));
    System.out.println("u[1] actual:   " + u[1].toString(16));
    assertThat(u[0]).as("u[0]").isEqualTo(EXPECTED_U0);
    assertThat(u[1]).as("u[1]").isEqualTo(EXPECTED_U1);
  }

  /**
   * Stage 2 simplified swu.
   */
  @Test
  void stage2_simplifiedSWU() {
    SimplifiedSWU swu = SimplifiedSWU.forP256();
    BigInteger[] swu0 = swu.map(EXPECTED_U0);
    BigInteger[] swu1 = swu.map(EXPECTED_U1);
    System.out.println("=== Stage 2: Simplified SWU (P-256) ===");
    System.out.println("SWU(u0).x expected: " + EXPECTED_Q0_X.toString(16));
    System.out.println("SWU(u0).x actual:   " + swu0[0].toString(16));
    System.out.println("SWU(u0).y expected: " + EXPECTED_Q0_Y.toString(16));
    System.out.println("SWU(u0).y actual:   " + swu0[1].toString(16));
    assertThat(swu0[0]).as("Q0.x").isEqualTo(EXPECTED_Q0_X);
    assertThat(swu0[1]).as("Q0.y").isEqualTo(EXPECTED_Q0_Y);
    assertThat(swu1[0]).as("Q1.x").isEqualTo(EXPECTED_Q1_X);
    assertThat(swu1[1]).as("Q1.y").isEqualTo(EXPECTED_Q1_Y);
  }

  /**
   * Stage 3 point addition.
   */
  @Test
  void stage3_pointAddition() {
    SimplifiedSWU swu = SimplifiedSWU.forP256();
    BigInteger[] swu0 = swu.map(EXPECTED_U0);
    BigInteger[] swu1 = swu.map(EXPECTED_U1);
    ECPoint Q0 = Curve.P256_CURVE.params().getCurve().createPoint(swu0[0], swu0[1]);
    ECPoint Q1 = Curve.P256_CURVE.params().getCurve().createPoint(swu1[0], swu1[1]);
    ECPoint P = Q0.add(Q1).normalize();
    System.out.println("=== Stage 3: Point Addition (Q0 + Q1) ===");
    System.out.println("P.x expected: " + EXPECTED_P_X.toString(16));
    System.out.println("P.x actual:   " + P.getXCoord().toBigInteger().toString(16));
    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }

  /**
   * Stage 4 full pipeline.
   */
  @Test
  void stage4_fullPipeline() {
    HashToCurve h2c = HashToCurve.forP256();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);
    ECPoint P = h2c.hashToCurve(msg, DST);
    System.out.println("=== Stage 4: Full Pipeline (P-256) ===");
    System.out.println("P.x expected: " + EXPECTED_P_X.toString(16));
    System.out.println("P.x actual:   " + P.getXCoord().toBigInteger().toString(16));
    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }
}
