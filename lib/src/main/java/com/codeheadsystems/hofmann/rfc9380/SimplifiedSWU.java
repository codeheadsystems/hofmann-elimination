package com.codeheadsystems.hofmann.rfc9380;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

/**
 * Implementation of Simplified SWU (Shallue-van de Woestijne-Ulas) mapping for AB == 0.
 * From RFC 9380 Section 6.6.2 and Appendix F.2.
 * <p>
 * Maps a field element to a point on the isogenous curve E': y^2 = x^3 + A'*x + B'
 * where A' and B' are chosen such that this mapping is well-defined.
 * <p>
 * Returns coordinate pairs rather than ECPoint objects, since E' is a different
 * curve than the target secp256k1.
 */
public class SimplifiedSWU {

  private final ECCurve curve; // used only for field arithmetic (same Fp for E and E')
  private final ECFieldElement A;
  private final ECFieldElement B;
  private final ECFieldElement Z;

  /**
   * Creates a SimplifiedSWU mapper for the given curve parameters.
   *
   * @param domainParams The EC domain parameters (provides the field Fp)
   * @param APrime       The A coefficient of the isogenous curve E'
   * @param BPrime       The B coefficient of the isogenous curve E'
   * @param ZValue       The Z parameter for the SWU algorithm
   */
  public SimplifiedSWU(ECDomainParameters domainParams, BigInteger APrime, BigInteger BPrime, BigInteger ZValue) {
    this.curve = domainParams.getCurve();
    BigInteger p = curve.getField().getCharacteristic();

    this.A = curve.fromBigInteger(APrime);
    this.B = curve.fromBigInteger(BPrime);

    // Ensure Z is in the valid range [0, p-1]
    BigInteger zMod = ZValue.mod(p);
    this.Z = curve.fromBigInteger(zMod);
  }

  /**
   * Maps a field element u to a point on the isogenous curve E'.
   * Implements the Simplified SWU algorithm from RFC 9380 Section 6.6.2.
   * <p>
   * Returns a coordinate pair [x, y] as BigIntegers, since the point is on E'
   * (different curve than the target).
   *
   * @param u Field element to map
   * @return BigInteger[2] containing [x, y] coordinates on E'
   */
  public BigInteger[] map(BigInteger u) {
    ECFieldElement uField = curve.fromBigInteger(u);
    ECFieldElement one = curve.fromBigInteger(BigInteger.ONE);

    // RFC 9380 Section 6.6.2 - step by step
    // 1. tv1 = u^2
    ECFieldElement tv1 = uField.square();

    // 2. tv1 = Z * tv1
    tv1 = Z.multiply(tv1);

    // 3. tv2 = tv1^2
    ECFieldElement tv2 = tv1.square();

    // 4. tv2 = tv2 + tv1
    tv2 = tv2.add(tv1);

    // 5. tv3 = tv2 + 1
    ECFieldElement tv3 = tv2.add(one);

    // 6. tv3 = B * tv3
    tv3 = B.multiply(tv3);

    // 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
    ECFieldElement tv4 = tv2.isZero() ? Z : tv2.negate();

    // 8. tv4 = A * tv4
    tv4 = A.multiply(tv4);

    // 9. tv2 = tv3^2
    tv2 = tv3.square();

    // 10. tv6 = tv4^2
    ECFieldElement tv6 = tv4.square();

    // 11. tv5 = A * tv6
    ECFieldElement tv5 = A.multiply(tv6);

    // 12. tv2 = tv2 + tv5
    tv2 = tv2.add(tv5);

    // 13. tv2 = tv2 * tv3
    tv2 = tv2.multiply(tv3);

    // 14. tv6 = tv6 * tv4
    tv6 = tv6.multiply(tv4);

    // 15. tv5 = B * tv6
    tv5 = B.multiply(tv6);

    // 16. tv2 = tv2 + tv5
    tv2 = tv2.add(tv5);

    // 17. x = tv1 * tv3
    ECFieldElement x = tv1.multiply(tv3);

    // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
    SqrtRatioResult result = sqrtRatio(tv2, tv6);
    boolean isGx1Square = result.isSquare;
    ECFieldElement y1 = result.root;

    // 19. y = tv1 * u
    ECFieldElement y = tv1.multiply(uField);

    // 20. y = y * y1
    y = y.multiply(y1);

    // 21. x = CMOV(x, tv3, is_gx1_square)
    x = isGx1Square ? tv3 : x;

    // 22. y = CMOV(y, y1, is_gx1_square)
    y = isGx1Square ? y1 : y;

    // 23. e1 = sgn0(u) == sgn0(y)
    boolean e1 = sgn0(uField) == sgn0(y);

    // 24. y = CMOV(-y, y, e1)
    y = e1 ? y : y.negate();

    // 25. x = x / tv4
    x = x.divide(tv4);

    // 26. return (x, y)
    return new BigInteger[]{x.toBigInteger(), y.toBigInteger()};
  }

  /**
   * Computes sqrt_ratio for p ≡ 3 (mod 4) as specified in RFC 9380 Appendix F.2.1.
   * <p>
   * Returns (isQR, y) where:
   * - If u/v is a quadratic residue: isQR = true,  y = sqrt(u/v)
   * - Otherwise:                     isQR = false, y = sqrt(Z * u / v)
   */
  private SqrtRatioResult sqrtRatio(ECFieldElement u, ECFieldElement v) {
    BigInteger p = curve.getField().getCharacteristic();

    // c1 = (p - 3) / 4   (integer arithmetic)
    BigInteger c1 = p.subtract(BigInteger.valueOf(3)).divide(BigInteger.valueOf(4));

    // c2 = sqrt(-Z) = (-Z)^((p+1)/4) for p ≡ 3 (mod 4)
    ECFieldElement c2 = modPow(Z.negate(), p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)));

    // 1. tv1 = v^2
    ECFieldElement tv1 = v.square();

    // 2. tv2 = u * v
    ECFieldElement tv2 = u.multiply(v);

    // 3. tv1 = tv1 * tv2             (= u * v^3)
    tv1 = tv1.multiply(tv2);

    // 4. y1 = tv1^c1                 (= (u * v^3)^((p-3)/4))
    ECFieldElement y1 = modPow(tv1, c1);

    // 5. y1 = y1 * tv2               (candidate sqrt(u/v))
    y1 = y1.multiply(tv2);

    // 6. y2 = y1 * c2                (candidate sqrt(Z * u / v))
    ECFieldElement y2 = y1.multiply(c2);

    // 7. tv3 = y1^2
    ECFieldElement tv3 = y1.square();

    // 8. tv3 = tv3 * v               (= y1^2 * v)
    tv3 = tv3.multiply(v);

    // 9. isQR = (tv3 == u)           (check if y1 = sqrt(u/v))
    boolean isQR = tv3.equals(u);

    // 10. y = CMOV(y2, y1, isQR)     (return y1 if square, y2 otherwise)
    ECFieldElement y = isQR ? y1 : y2;

    // 11. return (isQR, y)
    return new SqrtRatioResult(isQR, y);
  }

  /**
   * Sign function sgn0 from RFC 9380 Section 4.1.
   * Returns 0 if the field element is even, 1 if odd.
   */
  private int sgn0(ECFieldElement x) {
    return x.toBigInteger().testBit(0) ? 1 : 0;
  }

  /**
   * Modular exponentiation for field elements.
   * Computes base^exponent in the field using repeated squaring.
   */
  private ECFieldElement modPow(ECFieldElement base, BigInteger exponent) {
    ECFieldElement result = curve.fromBigInteger(BigInteger.ONE);
    ECFieldElement current = base;

    while (exponent.signum() > 0) {
      if (exponent.testBit(0)) {
        result = result.multiply(current);
      }
      current = current.square();
      exponent = exponent.shiftRight(1);
    }

    return result;
  }

  /**
   * Result of sqrt_ratio computation.
   */
  static class SqrtRatioResult {
    final boolean isSquare;
    final ECFieldElement root;

    SqrtRatioResult(boolean isSquare, ECFieldElement root) {
      this.isSquare = isSquare;
      this.root = root;
    }
  }

  /**
   * Factory method for secp256k1 isogenous curve parameters.
   * These are the standard parameters from RFC 9380 Section 8.7.
   *
   * @param domainParams secp256k1 domain parameters
   * @return SimplifiedSWU instance configured for secp256k1
   */
  public static SimplifiedSWU forSecp256k1(ECDomainParameters domainParams) {
    // A' for secp256k1 isogenous curve
    BigInteger APrime = new BigInteger(
        "3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533",
        16
    );

    // B' for secp256k1 isogenous curve
    BigInteger BPrime = BigInteger.valueOf(1771);

    // Z parameter
    BigInteger ZValue = BigInteger.valueOf(-11);

    return new SimplifiedSWU(domainParams, APrime, BPrime, ZValue);
  }

  /**
   * Factory method for P-256 curve parameters.
   * For P-256, A != 0, so Simplified SWU maps directly to the curve (no isogeny needed).
   * Parameters from RFC 9380 Section 8.2.
   *
   * @param domainParams P-256 domain parameters
   * @return SimplifiedSWU instance configured for P-256
   */
  public static SimplifiedSWU forP256(ECDomainParameters domainParams) {
    // P-256 curve coefficient A = -3 mod p
    BigInteger APrime = new BigInteger(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        16
    );

    // P-256 curve coefficient B
    BigInteger BPrime = new BigInteger(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        16
    );

    // Z = -10 mod p (from RFC 9380 Section 8.2, Table 5)
    BigInteger ZValue = BigInteger.valueOf(-10);

    return new SimplifiedSWU(domainParams, APrime, BPrime, ZValue);
  }
}
