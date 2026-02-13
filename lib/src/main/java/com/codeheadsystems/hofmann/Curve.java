package com.codeheadsystems.hofmann;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Function;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public record Curve(ECDomainParameters params, ECCurve curve, ECPoint g, BigInteger n, BigInteger h) {

  public static Curve P256_CURVE = new Curve(FACTORY().apply("P-256"));
  public static Curve SECP256K1_CURVE = new Curve(FACTORY().apply("secp256k1"));
  public static SecureRandom RANDOM = new SecureRandom();

  public Curve(ECDomainParameters params) {
    this(params, params.getCurve(), params.getG(), params.getN(), params.getH());
  }

  static Function<String, ECDomainParameters> FACTORY() {
    return name -> {
      X9ECParameters params = CustomNamedCurves.getByName(name);
      if (params == null) {
        throw new IllegalArgumentException("Unsupported curve: " + name);
      }
      return new ECDomainParameters(
          params.getCurve(),
          params.getG(),
          params.getN(),
          params.getH()
      );
    };
  }

  /**
   * Integer to Octet String Primitive (I2OSP) from RFC 8017.
   * Converts a non-negative integer to an octet string of specified length.
   */
  public static byte[] I2OSP(int value, int length) {
    if (value < 0 || value >= (1L << (8 * length))) {
      throw new IllegalArgumentException("Value too large for specified length");
    }
    byte[] result = new byte[length];
    for (int i = length - 1; i >= 0; i--) {
      result[i] = (byte) (value & 0xFF);
      value >>= 8;
    }
    return result;
  }

  /**
   * Generates a random scalar value for use in elliptic curve operations.
   *
   * @return A random scalar value in the range [1, n-1].
   */
  public BigInteger randomScaler() {
    BigInteger n = n();
    BigInteger key;
    do {
      key = new BigInteger(n.bitLength(), RANDOM);
    } while (key.compareTo(BigInteger.ONE) < 0 || key.compareTo(n) >= 0);
    return key;
  }

  public String toHex(final ECPoint point) {
    if (point == null) {
      throw new IllegalArgumentException("EC point must not be null");
    }
    return Hex.toHexString(point.getEncoded(true));
  }

  public ECPoint toEcPoint(final String hex) {
    if (hex == null || hex.isEmpty()) {
      throw new IllegalArgumentException("Hex string must not be null or empty");
    }
    return params().getCurve().decodePoint(Hex.decode(hex));
  }

}
