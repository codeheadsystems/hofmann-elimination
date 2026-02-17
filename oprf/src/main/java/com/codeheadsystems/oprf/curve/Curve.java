package com.codeheadsystems.oprf.curve;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public record Curve(ECDomainParameters params, ECCurve curve, ECPoint g, BigInteger n, BigInteger h) {

  public static final Curve P256_CURVE = loadCurve("P-256");
  public static final Curve P384_CURVE = loadCurve("P-384");
  public static final Curve P521_CURVE = loadCurve("P-521");
  public static final Curve SECP256K1_CURVE = loadCurve("secp256k1");
  private static final SecureRandom RANDOM = new SecureRandom();

  public Curve(ECDomainParameters params) {
    this(params, params.getCurve(), params.getG(), params.getN(), params.getH());
  }

  private static Curve loadCurve(String name) {
    X9ECParameters params = CustomNamedCurves.getByName(name);
    if (params == null) {
      throw new IllegalArgumentException("Unsupported curve: " + name);
    }
    return new Curve(new ECDomainParameters(
        params.getCurve(),
        params.getG(),
        params.getN(),
        params.getH()
    ));
  }

  /**
   * Generates a random scalar value for use in elliptic curve operations.
   *
   * @return A random scalar value in the range [1, n-1].
   */
  public BigInteger randomScalar() {
    BigInteger n = n();
    BigInteger key;
    do {
      key = new BigInteger(n.bitLength(), RANDOM);
    } while (key.compareTo(BigInteger.ONE) < 0 || key.compareTo(n) >= 0);
    return key;
  }

}
