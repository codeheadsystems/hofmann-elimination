package com.codeheadsystems.oprf.rfc9380;

import com.codeheadsystems.oprf.curve.Curve;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of the 3-isogeny map from the isogenous curve E' to secp256k1.
 * From RFC 9380 Appendix E.1 and Section 8.7.
 * <p>
 * The isogeny is defined by rational functions that map points from E' to the target curve.
 */
public class IsogenyMap {

  private final ECCurve targetCurve;
  private final BigInteger[] xNumCoeffs;
  private final BigInteger[] xDenCoeffs;
  private final BigInteger[] yNumCoeffs;
  private final BigInteger[] yDenCoeffs;

  /**
   * Creates an IsogenyMap with the given rational function coefficients.
   *
   * @param targetCurve Target curve (secp256k1)
   * @param xNumCoeffs  Coefficients for x numerator polynomial
   * @param xDenCoeffs  Coefficients for x denominator polynomial
   * @param yNumCoeffs  Coefficients for y numerator polynomial
   * @param yDenCoeffs  Coefficients for y denominator polynomial
   */
  private IsogenyMap(ECCurve targetCurve,
                     BigInteger[] xNumCoeffs,
                     BigInteger[] xDenCoeffs,
                     BigInteger[] yNumCoeffs,
                     BigInteger[] yDenCoeffs) {
    this.targetCurve = targetCurve;
    this.xNumCoeffs = xNumCoeffs;
    this.xDenCoeffs = xDenCoeffs;
    this.yNumCoeffs = yNumCoeffs;
    this.yDenCoeffs = yDenCoeffs;
  }

  /**
   * Factory method for secp256k1 3-isogeny map.
   * Coefficients are from RFC 9380 Appendix E.1 for the secp256k1 3-isogeny.
   *
   * @return IsogenyMap instance configured for secp256k1
   */
  public static IsogenyMap forSecp256k1() {
    // x-coordinate numerator coefficients (degree 3)
    BigInteger[] xNum = {
        new BigInteger("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7", 16),
        new BigInteger("07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581", 16),
        new BigInteger("534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262", 16),
        new BigInteger("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c", 16)
    };

    // x-coordinate denominator coefficients (degree 2)
    BigInteger[] xDen = {
        new BigInteger("d35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b", 16),
        new BigInteger("edadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14", 16),
        BigInteger.ONE
    };

    // y-coordinate numerator coefficients (degree 3)
    BigInteger[] yNum = {
        new BigInteger("4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c", 16),
        new BigInteger("c75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3", 16),
        new BigInteger("29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931", 16),
        new BigInteger("2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84", 16)
    };

    // y-coordinate denominator coefficients (degree 3)
    BigInteger[] yDen = {
        new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b", 16),
        new BigInteger("7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573", 16),
        new BigInteger("6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f", 16),
        BigInteger.ONE
    };

    return new IsogenyMap(Curve.SECP256K1_CURVE.curve(), xNum, xDen, yNum, yDen);
  }

  /**
   * Maps coordinate pairs from the isogenous curve E' to a point on the target curve.
   *
   * @param coords BigInteger[2] containing [x', y'] from E'
   * @return Point on secp256k1 (x, y)
   */
  public ECPoint map(BigInteger[] coords) {
    ECFieldElement xPrime = targetCurve.fromBigInteger(coords[0]);
    ECFieldElement yPrime = targetCurve.fromBigInteger(coords[1]);

    // Compute x = x_num(x') / x_den(x')
    ECFieldElement xNum = evalPolynomial(xPrime, xNumCoeffs);
    ECFieldElement xDen = evalPolynomial(xPrime, xDenCoeffs);
    ECFieldElement x = xNum.divide(xDen);

    // Compute y = y' * y_num(x') / y_den(x')
    ECFieldElement yNum = evalPolynomial(xPrime, yNumCoeffs);
    ECFieldElement yDen = evalPolynomial(xPrime, yDenCoeffs);
    ECFieldElement y = yPrime.multiply(yNum).divide(yDen);

    return targetCurve.createPoint(x.toBigInteger(), y.toBigInteger());
  }

  /**
   * Evaluates a polynomial at a given point using Horner's method.
   * P(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ... + coeffs[n]*x^n
   */
  private ECFieldElement evalPolynomial(ECFieldElement x, BigInteger[] coeffs) {
    if (coeffs.length == 0) {
      return targetCurve.fromBigInteger(BigInteger.ZERO);
    }

    // Start from the highest degree coefficient
    ECFieldElement result = targetCurve.fromBigInteger(coeffs[coeffs.length - 1]);

    // Horner's method: result = result * x + coeffs[i]
    for (int i = coeffs.length - 2; i >= 0; i--) {
      result = result.multiply(x).add(targetCurve.fromBigInteger(coeffs[i]));
    }

    return result;
  }
}
