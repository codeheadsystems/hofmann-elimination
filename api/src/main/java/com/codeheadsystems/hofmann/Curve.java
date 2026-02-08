package com.codeheadsystems.hofmann;

import static org.bouncycastle.util.encoders.Hex.decode;
import static org.bouncycastle.util.encoders.Hex.toHexString;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Function;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public interface Curve {

  String DEFAULT_CURVE_NAME = "secp256k1";
  ECDomainParameters DEFAULT_CURVE = FACTORY().apply(DEFAULT_CURVE_NAME);
  SecureRandom RANDOM = new SecureRandom();

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

  static byte[] HASH(final byte[] bytes) {
    Blake3Digest digest = new Blake3Digest();
    digest.update(bytes, 0, bytes.length);
    byte[] hash = new byte[digest.getDigestSize()];
    digest.doFinal(hash, 0);
    return hash;
  }

  /**
   * Generates a random scalar value for use in elliptic curve operations.
   *
   * @return A random scalar value in the range [1, n-1].
   */
  static BigInteger RANDOM_SCALER() {
    BigInteger n = DEFAULT_CURVE.getN();
    BigInteger key;
    do {
      key = new BigInteger(n.bitLength(), RANDOM);
    } while (key.compareTo(BigInteger.ONE) < 0 || key.compareTo(n) >= 0);
    return key;
  }

  static String ECPOINT_TO_HEX(final ECPoint blindedPoint) {
    if (blindedPoint == null) {
      return null;
    }
    byte[] encoded = blindedPoint.getEncoded(true);
    return BYTES_TO_HEX(encoded);
  }

  static ECPoint HEX_TO_ECPOINT(final String hex) {
    if (hex == null || hex.isEmpty()) {
      return null;
    }
    byte[] encoded = decode(hex);
    return DEFAULT_CURVE.getCurve().decodePoint(encoded);
  }

  static String BYTES_TO_HEX(final byte[] bytes) {
    return toHexString(bytes);
  }

}
