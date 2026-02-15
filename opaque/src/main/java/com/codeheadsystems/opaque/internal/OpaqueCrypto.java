package com.codeheadsystems.opaque.internal;

import static com.codeheadsystems.oprf.curve.OctetStringUtils.concat;

import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.codeheadsystems.oprf.rfc9497.OprfSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Low-level cryptographic primitives for OPAQUE.
 * Wraps BouncyCastle HKDF, HMAC, SHA-256, and EC operations.
 */
public class OpaqueCrypto {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final byte[] EMPTY_SALT = new byte[32]; // HashLen zeros per RFC 5869

  private OpaqueCrypto() {
  }

  /**
   * HKDF-Extract(salt, ikm) = HMAC-SHA256(salt, ikm). Empty salt uses 32 zero bytes.
   */
  public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
    byte[] actualSalt = (salt == null || salt.length == 0) ? EMPTY_SALT : salt;
    HMac hmac = new HMac(new SHA256Digest());
    hmac.init(new KeyParameter(actualSalt));
    hmac.update(ikm, 0, ikm.length);
    byte[] prk = new byte[32];
    hmac.doFinal(prk, 0);
    return prk;
  }

  /**
   * HKDF-Expand(prk, info, len) per RFC 5869 §2.3.
   * Implemented directly via HMAC to avoid BouncyCastle API variations.
   */
  public static byte[] hkdfExpand(byte[] prk, byte[] info, int len) {
    HMac hmac = new HMac(new SHA256Digest());
    hmac.init(new KeyParameter(prk));
    byte[] result = new byte[len];
    byte[] t = new byte[0];
    int copied = 0;
    int counter = 1;
    while (copied < len) {
      hmac.reset();
      hmac.update(t, 0, t.length);
      hmac.update(info, 0, info.length);
      hmac.update((byte) counter);
      t = new byte[32];
      hmac.doFinal(t, 0);
      int toCopy = Math.min(len - copied, 32);
      System.arraycopy(t, 0, result, copied, toCopy);
      copied += toCopy;
      counter++;
    }
    return result;
  }

  /**
   * HKDF-Expand-Label(secret, label, context, length) in OPAQUE TLS-style format:
   * info = I2OSP(length, 2) || I2OSP(len("OPAQUE-" + label), 1) || "OPAQUE-" + label
   * || I2OSP(len(context), 1) || context
   */
  public static byte[] hkdfExpandLabel(byte[] secret, byte[] label, byte[] context, int length) {
    byte[] prefix = "OPAQUE-".getBytes(StandardCharsets.US_ASCII);
    byte[] fullLabel = concat(prefix, label);
    byte[] info = concat(
        OctetStringUtils.I2OSP(length, 2),
        OctetStringUtils.I2OSP(fullLabel.length, 1),
        fullLabel,
        OctetStringUtils.I2OSP(context.length, 1),
        context
    );
    return hkdfExpand(secret, info, length);
  }

  /**
   * HMAC-SHA256(key, data).
   */
  public static byte[] hmacSha256(byte[] key, byte[] data) {
    HMac hmac = new HMac(new SHA256Digest());
    hmac.init(new KeyParameter(key));
    hmac.update(data, 0, data.length);
    byte[] out = new byte[32];
    hmac.doFinal(out, 0);
    return out;
  }

  /**
   * SHA-256(data).
   */
  public static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }

  /**
   * Computes DH: serializes (privateKey * publicKey) as compressed SEC1 (33 bytes).
   */
  public static byte[] dhP256(BigInteger privateKey, ECPoint publicKey) {
    ECPoint result = publicKey.multiply(privateKey).normalize();
    return result.getEncoded(true); // 33-byte compressed SEC1 point
  }

  /**
   * A derived P-256 AKE key pair.
   *
   * @param privateKey     the private key scalar
   * @param publicKeyBytes 33-byte compressed SEC1 public key
   */
  public record AkeKeyPair(BigInteger privateKey, byte[] publicKeyBytes) {
  }

  /**
   * Derives a P-256 AKE key pair from a seed.
   */
  public static AkeKeyPair deriveAkeKeyPair(byte[] seed) {
    BigInteger sk = OprfSuite.deriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair".getBytes(
        StandardCharsets.US_ASCII));
    ECPoint pk = Curve.P256_CURVE.g().multiply(sk).normalize();
    return new AkeKeyPair(sk, pk.getEncoded(true));
  }

  /**
   * Generates a random 32-byte seed.
   */
  public static byte[] randomBytes(int len) {
    byte[] out = new byte[len];
    RANDOM.nextBytes(out);
    return out;
  }

  /**
   * Serializes an EC point to compressed SEC1 (33 bytes).
   */
  public static byte[] serializePoint(ECPoint p) {
    return p.normalize().getEncoded(true);
  }

  /**
   * Deserializes a compressed SEC1 byte array to an EC point on P-256.
   */
  public static ECPoint deserializePoint(byte[] bytes) {
    return Curve.P256_CURVE.params().getCurve().decodePoint(bytes);
  }

  /**
   * Interprets a 32-byte big-endian array as a P-256 private key scalar.
   */
  public static BigInteger scalarFromBytes(byte[] bytes) {
    return new BigInteger(1, bytes); // positive big-endian
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
