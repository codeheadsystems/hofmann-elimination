package com.codeheadsystems.hofmann;

import static org.bouncycastle.util.encoders.Hex.decode;
import static org.bouncycastle.util.encoders.Hex.toHexString;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.math.ec.ECPoint;

public class EcUtilities {

  private EcUtilities() {
  }

  static byte[] HASH(final byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return digest.digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }

  public static String ECPOINT_TO_HEX(final ECPoint blindedPoint) {
    if (blindedPoint == null) {
      return null;
    }
    byte[] encoded = blindedPoint.getEncoded(true);
    return BYTES_TO_HEX(encoded);
  }

  public static ECPoint HEX_TO_ECPOINT(final String hex) {
    if (hex == null || hex.isEmpty()) {
      return null;
    }
    byte[] encoded = decode(hex);
    return Curve.P256_CURVE.params().getCurve().decodePoint(encoded);
  }

  public static String BYTES_TO_HEX(final byte[] bytes) {
    return toHexString(bytes);
  }
}
