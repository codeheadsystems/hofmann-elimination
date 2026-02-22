package com.codeheadsystems.rfc.opaque.config;

import static com.codeheadsystems.rfc.common.ByteUtils.concat;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;

/**
 * OPAQUE-specific cipher suite wrapper over an OPRF cipher suite.
 * Provides OPAQUE protocol size constants derived from the underlying suite.
 * <p>
 * Supported suites:
 * <ul>
 *   <li>P256_SHA256 — P-256 / SHA-256 (RFC 9807 reference suite)</li>
 *   <li>P384_SHA384 — P-384 / SHA-384</li>
 *   <li>P521_SHA512 — P-521 / SHA-512</li>
 * </ul>
 */
public record OpaqueCipherSuite(OprfCipherSuite oprfSuite) {

  /**
   * The constant P256_SHA256.
   */
  public static final OpaqueCipherSuite P256_SHA256 = new OpaqueCipherSuite(OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build());
  /**
   * The constant P384_SHA384.
   */
  public static final OpaqueCipherSuite P384_SHA384 = new OpaqueCipherSuite(OprfCipherSuite.builder().withSuite(CurveHashSuite.P384_SHA384).build());
  /**
   * The constant P521_SHA512.
   */
  public static final OpaqueCipherSuite P521_SHA512 = new OpaqueCipherSuite(OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build());

  /**
   * Returns the OPAQUE cipher suite for the given name.  Accepted names: {@code "P256_SHA256"},
   * {@code "P384_SHA384"}, {@code "P521_SHA512"}.
   *
   * @param name the name
   * @return the opaque cipher suite
   * @throws IllegalArgumentException for unrecognised names
   */
  public static OpaqueCipherSuite fromName(String name) {
    return switch (name) {
      case "P256_SHA256" -> P256_SHA256;
      case "P384_SHA384" -> P384_SHA384;
      case "P521_SHA512" -> P521_SHA512;
      default -> throw new IllegalArgumentException("Unknown OPAQUE cipher suite: " + name
          + ". Valid values: P256_SHA256, P384_SHA384, P521_SHA512");
    };
  }

  /**
   * Compressed public key size in bytes (33, 49, or 67).
   *
   * @return the int
   */
  public int Npk() {
    return oprfSuite().elementSize();
  }

  /**
   * Scalar (private key) size in bytes (32, 48, or 66).
   *
   * @return the int
   */
  public int Nsk() {
    return (oprfSuite().groupSpec().groupOrder().bitLength() + 7) / 8;
  }

  /**
   * Hash output length in bytes (32, 48, or 64).
   *
   * @return the int
   */
  public int Nh() {
    return oprfSuite().hashOutputLength();
  }

  /**
   * MAC output length — equals hash output length.
   *
   * @return the int
   */
  public int Nm() {
    return Nh();
  }

  /**
   * HKDF output length — equals hash output length.
   *
   * @return the int
   */
  public int Nx() {
    return Nh();
  }

  /**
   * OPRF evaluated element size — equals compressed public key size.
   *
   * @return the int
   */
  public int Noe() {
    return Npk();
  }

  /**
   * OPRF key size — equals scalar size.
   *
   * @return the int
   */
  public int Nok() {
    return Nsk();
  }

  /**
   * Nonce length — always 32, suite-independent.
   *
   * @return the int
   */
  public int Nn() {
    return 32;
  }

  /**
   * Envelope size = Nn + Nm.
   *
   * @return the int
   */
  public int envelopeSize() {
    return Nn() + Nm();
  }

  /**
   * Masked response size = Npk + envelopeSize.
   *
   * @return the int
   */
  public int maskedResponseSize() {
    return Npk() + envelopeSize();
  }

  // ─── Cryptographic operations ───────────────────────────────────────────────

  /**
   * HKDF-Extract(salt, ikm) = HMAC-H(salt, ikm).
   * Empty salt uses HashLen zeros per RFC 5869.
   *
   * @param salt the salt
   * @param ikm  the ikm
   * @return the byte [ ]
   */
  public byte[] hkdfExtract(byte[] salt, byte[] ikm) {
    byte[] emptySalt = new byte[Nh()];
    byte[] actualSalt = (salt == null || salt.length == 0) ? emptySalt : salt;
    return oprfSuite().hmac(actualSalt, ikm);
  }

  /**
   * HKDF-Expand(prk, info, len) per RFC 5869 §2.3.
   *
   * @param prk  the prk
   * @param info the info
   * @param len  the len
   * @return the byte [ ]
   */
  public byte[] hkdfExpand(byte[] prk, byte[] info, int len) {
    int hashLen = Nh();
    byte[] result = new byte[len];
    byte[] t = new byte[0];
    int copied = 0;
    int counter = 1;
    while (copied < len) {
      byte[] input = concat(t, info, new byte[]{(byte) counter});
      t = oprfSuite().hmac(prk, input);
      int toCopy = Math.min(len - copied, hashLen);
      System.arraycopy(t, 0, result, copied, toCopy);
      copied += toCopy;
      counter++;
    }
    return result;
  }

  /**
   * HKDF-Expand-Label(secret, label, context, length) in OPAQUE TLS-style format.
   *
   * @param secret  the secret
   * @param label   the label
   * @param context the context
   * @param length  the length
   * @return the byte [ ]
   */
  public byte[] hkdfExpandLabel(byte[] secret, byte[] label, byte[] context, int length) {
    byte[] prefix = "OPAQUE-".getBytes(StandardCharsets.US_ASCII);
    byte[] fullLabel = concat(prefix, label);
    byte[] info = concat(
        ByteUtils.I2OSP(length, 2),
        ByteUtils.I2OSP(fullLabel.length, 1),
        fullLabel,
        ByteUtils.I2OSP(context.length, 1),
        context
    );
    return hkdfExpand(secret, info, length);
  }

  /**
   * HMAC-H(key, data) using the suite's hash.
   *
   * @param key  the key
   * @param data the data
   * @return the byte [ ]
   */
  public byte[] hmac(byte[] key, byte[] data) {
    return oprfSuite().hmac(key, data);
  }

  /**
   * H(data) using the suite's hash.
   *
   * @param data the data
   * @return the byte [ ]
   */
  public byte[] hash(byte[] data) {
    return oprfSuite().hash(data);
  }

  /**
   * Deserializes a compressed SEC1 byte array to an EC point using the suite's curve.
   * Validates the point is on the curve and not the identity element to prevent
   * invalid-curve and small-subgroup attacks on DH computations.
   *
   * @param bytes the bytes
   * @return the ec point
   */
  public ECPoint deserializePoint(byte[] bytes) {
    GroupSpec wgs = oprfSuite().groupSpec();
    return wgs.deserializePoint(bytes);
  }

  /**
   * Derives an AKE key pair from a seed using the suite's deriveKeyPair.
   *
   * @param seed the seed
   * @return the ake key pair
   */
  public AkeKeyPair deriveAkeKeyPair(byte[] seed) {
    BigInteger sk = oprfSuite().deriveKeyPair(seed,
        "OPAQUE-DeriveDiffieHellmanKeyPair".getBytes(StandardCharsets.US_ASCII));
    byte[] pkBytes = oprfSuite().groupSpec().scalarMultiplyGenerator(sk);
    return new AkeKeyPair(sk, pkBytes);
  }

  /**
   * A derived AKE key pair.
   */
  public record AkeKeyPair(BigInteger privateKey, byte[] publicKeyBytes) {
  }
}
