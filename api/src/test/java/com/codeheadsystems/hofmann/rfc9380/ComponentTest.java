package com.codeheadsystems.hofmann.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * Debug tests to verify each stage of the RFC 9380 hash-to-curve pipeline.
 * Uses intermediate test vectors from RFC 9380 Appendix J.8.1.
 */
public class ComponentTest {

  private static final byte[] DST = "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.UTF_8);

  // Test vector 1: msg = "" (empty string)
  private static final BigInteger EXPECTED_U0 = new BigInteger("6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3", 16);
  private static final BigInteger EXPECTED_U1 = new BigInteger("1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16", 16);

  // Q0 and Q1 are after both SWU + isogeny (on secp256k1)
  private static final BigInteger EXPECTED_Q0_X = new BigInteger("74519ef88b32b425a095e4ebcc84d81b64e9e2c2675340a720bb1a1857b99f1e", 16);
  private static final BigInteger EXPECTED_Q0_Y = new BigInteger("c174fa322ab7c192e11748beed45b508e9fdb1ce046dee9c2cd3a2a86b410936", 16);
  private static final BigInteger EXPECTED_Q1_X = new BigInteger("44548adb1b399263ded3510554d28b4bead34b8cf9a37b4bd0bd2ba4db87ae63", 16);
  private static final BigInteger EXPECTED_Q1_Y = new BigInteger("96eb8e2faf05e368efe5957c6167001760233e6dd2487516b46ae725c4cce0c6", 16);

  private static final BigInteger EXPECTED_P_X = new BigInteger("c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346", 16);
  private static final BigInteger EXPECTED_P_Y = new BigInteger("64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067", 16);

  @Test
  void stage1_hashToField() {
    HashToField h2f = HashToField.forSecp256k1();
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    BigInteger[] u = h2f.hashToField(msg, DST, 2);

    System.out.println("=== Stage 1: hash_to_field ===");
    System.out.println("u[0] expected: " + EXPECTED_U0.toString(16));
    System.out.println("u[0] actual:   " + u[0].toString(16));
    System.out.println("u[1] expected: " + EXPECTED_U1.toString(16));
    System.out.println("u[1] actual:   " + u[1].toString(16));

    assertThat(u[0]).as("u[0]").isEqualTo(EXPECTED_U0);
    assertThat(u[1]).as("u[1]").isEqualTo(EXPECTED_U1);
  }

  @Test
  void stage2_simplifiedSWU() {
    SimplifiedSWU swu = SimplifiedSWU.forSecp256k1(Curve.DEFAULT_CURVE);

    BigInteger[] swu0 = swu.map(EXPECTED_U0);
    BigInteger[] swu1 = swu.map(EXPECTED_U1);

    System.out.println("=== Stage 2: Simplified SWU (on E') ===");
    System.out.println("SWU(u0).x = " + swu0[0].toString(16));
    System.out.println("SWU(u0).y = " + swu0[1].toString(16));
    System.out.println("SWU(u1).x = " + swu1[0].toString(16));
    System.out.println("SWU(u1).y = " + swu1[1].toString(16));

    // Verify the SWU outputs satisfy E': y^2 = x^3 + A'x + B'
    BigInteger p = Curve.DEFAULT_CURVE.getCurve().getField().getCharacteristic();
    BigInteger APrime = new BigInteger("3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 16);
    BigInteger BPrime = BigInteger.valueOf(1771);

    BigInteger lhs0 = swu0[1].modPow(BigInteger.TWO, p);
    BigInteger rhs0 = swu0[0].modPow(BigInteger.valueOf(3), p)
        .add(APrime.multiply(swu0[0]).mod(p))
        .add(BPrime)
        .mod(p);
    System.out.println("SWU(u0) on E': " + lhs0.equals(rhs0));
    assertThat(lhs0).as("SWU(u0) should be on E'").isEqualTo(rhs0);

    BigInteger lhs1 = swu1[1].modPow(BigInteger.TWO, p);
    BigInteger rhs1 = swu1[0].modPow(BigInteger.valueOf(3), p)
        .add(APrime.multiply(swu1[0]).mod(p))
        .add(BPrime)
        .mod(p);
    System.out.println("SWU(u1) on E': " + lhs1.equals(rhs1));
    assertThat(lhs1).as("SWU(u1) should be on E'").isEqualTo(rhs1);
  }

  @Test
  void stage3_isogenyMap() {
    SimplifiedSWU swu = SimplifiedSWU.forSecp256k1(Curve.DEFAULT_CURVE);
    IsogenyMap iso = IsogenyMap.forSecp256k1(Curve.DEFAULT_CURVE.getCurve());

    BigInteger[] swu0 = swu.map(EXPECTED_U0);
    ECPoint Q0 = iso.map(swu0);

    BigInteger[] swu1 = swu.map(EXPECTED_U1);
    ECPoint Q1 = iso.map(swu1);

    System.out.println("=== Stage 3: SWU + Isogeny = map_to_curve ===");
    System.out.println("Q0.x expected: " + EXPECTED_Q0_X.toString(16));
    System.out.println("Q0.x actual:   " + Q0.getXCoord().toBigInteger().toString(16));
    System.out.println("Q0.y expected: " + EXPECTED_Q0_Y.toString(16));
    System.out.println("Q0.y actual:   " + Q0.getYCoord().toBigInteger().toString(16));
    System.out.println("Q1.x expected: " + EXPECTED_Q1_X.toString(16));
    System.out.println("Q1.x actual:   " + Q1.getXCoord().toBigInteger().toString(16));
    System.out.println("Q1.y expected: " + EXPECTED_Q1_Y.toString(16));
    System.out.println("Q1.y actual:   " + Q1.getYCoord().toBigInteger().toString(16));

    assertThat(Q0.getXCoord().toBigInteger()).as("Q0.x").isEqualTo(EXPECTED_Q0_X);
    assertThat(Q0.getYCoord().toBigInteger()).as("Q0.y").isEqualTo(EXPECTED_Q0_Y);
    assertThat(Q1.getXCoord().toBigInteger()).as("Q1.x").isEqualTo(EXPECTED_Q1_X);
    assertThat(Q1.getYCoord().toBigInteger()).as("Q1.y").isEqualTo(EXPECTED_Q1_Y);
  }

  @Test
  void stage4_fullPipeline() {
    HashToCurve h2c = HashToCurve.forSecp256k1(Curve.DEFAULT_CURVE);
    byte[] msg = "".getBytes(StandardCharsets.UTF_8);

    ECPoint P = h2c.hashToCurve(msg, DST);

    System.out.println("=== Stage 4: Full Pipeline ===");
    System.out.println("P.x expected: " + EXPECTED_P_X.toString(16));
    System.out.println("P.x actual:   " + P.getXCoord().toBigInteger().toString(16));
    System.out.println("P.y expected: " + EXPECTED_P_Y.toString(16));
    System.out.println("P.y actual:   " + P.getYCoord().toBigInteger().toString(16));

    assertThat(P.getXCoord().toBigInteger()).as("P.x").isEqualTo(EXPECTED_P_X);
    assertThat(P.getYCoord().toBigInteger()).as("P.y").isEqualTo(EXPECTED_P_Y);
  }
}
