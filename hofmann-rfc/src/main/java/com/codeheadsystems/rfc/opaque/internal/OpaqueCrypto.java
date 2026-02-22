package com.codeheadsystems.rfc.opaque.internal;

import static com.codeheadsystems.rfc.common.ByteUtils.concat;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Low-level cryptographic primitives for OPAQUE.
 * All suite-dependent operations accept an {@link OpaqueCipherSuite} as the first parameter.
 */
public class OpaqueCrypto {

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
        ByteUtils.I2OSP(length, 2),
        ByteUtils.I2OSP(fullLabel.length, 1),
        fullLabel,
        ByteUtils.I2OSP(context.length, 1),
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
    GroupSpec wgs = suite.oprfSuite().groupSpec();
    return wgs.deserializePoint(bytes);
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
   * A derived AKE key pair.
   */
  public record AkeKeyPair(BigInteger privateKey, byte[] publicKeyBytes) {
  }
}
