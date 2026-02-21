package com.codeheadsystems.opaque.internal;

import static com.codeheadsystems.ellipticcurve.curve.OctetStringUtils.concat;

import com.codeheadsystems.ellipticcurve.curve.OctetStringUtils;
import com.codeheadsystems.ellipticcurve.rfc9380.WeierstrassGroupSpecImpl;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Low-level cryptographic primitives for OPAQUE.
 * All suite-dependent operations accept an {@link OpaqueCipherSuite} as the first parameter.
 */
public class OpaqueCrypto {

  private static final SecureRandom RANDOM = new SecureRandom();

  private OpaqueCrypto() {
  }

  // ─── Suite-aware core methods ────────────────────────────────────────────────

  /**
   * HKDF-Extract(salt, ikm) = HMAC-H(salt, ikm).
   * Empty salt uses HashLen zeros per RFC 5869.
   */
  public static byte[] hkdfExtract(OpaqueCipherSuite suite, byte[] salt, byte[] ikm) {
    byte[] emptySalt = new byte[suite.Nh()];
    byte[] actualSalt = (salt == null || salt.length == 0) ? emptySalt : salt;
    return suite.oprfSuite().hmac(actualSalt, ikm);
  }

  /**
   * HKDF-Expand(prk, info, len) per RFC 5869 §2.3.
   */
  public static byte[] hkdfExpand(OpaqueCipherSuite suite, byte[] prk, byte[] info, int len) {
    int hashLen = suite.Nh();
    byte[] result = new byte[len];
    byte[] t = new byte[0];
    int copied = 0;
    int counter = 1;
    while (copied < len) {
      byte[] input = concat(t, info, new byte[]{(byte) counter});
      t = suite.oprfSuite().hmac(prk, input);
      int toCopy = Math.min(len - copied, hashLen);
      System.arraycopy(t, 0, result, copied, toCopy);
      copied += toCopy;
      counter++;
    }
    return result;
  }

  /**
   * HKDF-Expand-Label(secret, label, context, length) in OPAQUE TLS-style format.
   */
  public static byte[] hkdfExpandLabel(OpaqueCipherSuite suite, byte[] secret, byte[] label,
                                       byte[] context, int length) {
    byte[] prefix = "OPAQUE-".getBytes(StandardCharsets.US_ASCII);
    byte[] fullLabel = concat(prefix, label);
    byte[] info = concat(
        OctetStringUtils.I2OSP(length, 2),
        OctetStringUtils.I2OSP(fullLabel.length, 1),
        fullLabel,
        OctetStringUtils.I2OSP(context.length, 1),
        context
    );
    return hkdfExpand(suite, secret, info, length);
  }

  /**
   * HMAC-H(key, data) using the suite's hash.
   */
  public static byte[] hmac(OpaqueCipherSuite suite, byte[] key, byte[] data) {
    return suite.oprfSuite().hmac(key, data);
  }

  /**
   * H(data) using the suite's hash.
   */
  public static byte[] hash(OpaqueCipherSuite suite, byte[] data) {
    return suite.oprfSuite().hash(data);
  }

  /**
   * Computes DH: serializes (privateKey * publicKey) as compressed SEC1.
   */
  public static byte[] dhECDH(OpaqueCipherSuite suite, BigInteger privateKey, ECPoint publicKey) {
    ECPoint result = publicKey.multiply(privateKey).normalize();
    return result.getEncoded(true);
  }

  /**
   * Deserializes a compressed SEC1 byte array to an EC point using the suite's curve.
   * Validates the point is on the curve and not the identity element to prevent
   * invalid-curve and small-subgroup attacks on DH computations.
   */
  public static ECPoint deserializePoint(OpaqueCipherSuite suite, byte[] bytes) {
    WeierstrassGroupSpecImpl wgs = (WeierstrassGroupSpecImpl) suite.oprfSuite().groupSpec();
    return wgs.deserializePoint(bytes);
  }

  /**
   * A derived AKE key pair.
   */
  public record AkeKeyPair(BigInteger privateKey, byte[] publicKeyBytes) {
  }

  /**
   * Derives an AKE key pair from a seed using the suite's deriveKeyPair.
   */
  public static AkeKeyPair deriveAkeKeyPair(OpaqueCipherSuite suite, byte[] seed) {
    BigInteger sk = suite.oprfSuite().deriveKeyPair(seed,
        "OPAQUE-DeriveDiffieHellmanKeyPair".getBytes(StandardCharsets.US_ASCII));
    byte[] pkBytes = suite.oprfSuite().groupSpec().scalarMultiplyGenerator(sk);
    return new AkeKeyPair(sk, pkBytes);
  }

  // ─── Suite-independent utilities ─────────────────────────────────────────────

  /**
   * Generates a random byte array of the given length.
   */
  public static byte[] randomBytes(int len) {
    byte[] out = new byte[len];
    RANDOM.nextBytes(out);
    return out;
  }

  /**
   * Serializes an EC point to compressed SEC1.
   */
  public static byte[] serializePoint(ECPoint p) {
    return p.normalize().getEncoded(true);
  }

  /**
   * Interprets a big-endian byte array as a private key scalar.
   */
  public static BigInteger scalarFromBytes(byte[] bytes) {
    return new BigInteger(1, bytes);
  }

  /**
   * XOR two byte arrays of equal length.
   */
  public static byte[] xor(byte[] a, byte[] b) {
    if (a.length != b.length) {
      throw new IllegalArgumentException("XOR arrays must have equal length: " + a.length + " vs " + b.length);
    }
    byte[] out = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      out[i] = (byte) (a[i] ^ b[i]);
    }
    return out;
  }
}
