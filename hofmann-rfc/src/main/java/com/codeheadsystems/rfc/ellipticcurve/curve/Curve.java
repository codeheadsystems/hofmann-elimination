package com.codeheadsystems.rfc.ellipticcurve.curve;

import java.math.BigInteger;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The type Curve.
 */
public record Curve(ECDomainParameters params, ECCurve curve, ECPoint g, BigInteger n, BigInteger h) {

  /**
   * The constant P256_CURVE.
   */
  public static final Curve P256_CURVE = loadCurve("P-256");
  /**
   * The constant P384_CURVE.
   */
  public static final Curve P384_CURVE = loadCurve("P-384");
  /**
   * The constant P521_CURVE.
   */
  public static final Curve P521_CURVE = loadCurve("P-521");
  /**
   * The constant SECP256K1_CURVE.
   */
  public static final Curve SECP256K1_CURVE = loadCurve("secp256k1");

  /**
   * Instantiates a new Curve.
   *
   * @param params the params
   */
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

}
