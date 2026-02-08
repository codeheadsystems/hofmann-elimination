package com.codeheadsystems.hofmann.impl;

import com.codeheadsystems.hofmann.Client;
import com.codeheadsystems.hofmann.Curve;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public class ClientImpl implements Client {

  private final String customerId;

  public ClientImpl(final String customerId) {
    this.customerId = customerId;
  }

  @Override
  public String customerId() {
    return customerId;
  }

  /*
   * 1. Converts the hash to a scalar in the valid range [1, n-1] using modular arithmetic
   * 2. Multiplies the generator point G by the scalar to produce a deterministic point on the curve
   * 3. Normalizes the point for consistent representation
   */
  @Override
  public ECPoint hashToCurve(final byte[] hash) {
    BigInteger scalar = new BigInteger(1, hash)
        .mod(Curve.DEFAULT_CURVE.getN().subtract(BigInteger.ONE))
        .add(BigInteger.ONE);

    // Multiply the generator point by the scalar to get a point on the curve
    return Curve.DEFAULT_CURVE.getG().multiply(scalar).normalize();
  }

}
