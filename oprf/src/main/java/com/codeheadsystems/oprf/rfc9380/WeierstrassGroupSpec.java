package com.codeheadsystems.oprf.rfc9380;

import com.codeheadsystems.oprf.curve.Curve;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECPoint;

/**
 * {@link GroupSpec} implementation for Weierstrass elliptic curves (P-256, P-384, P-521, secp256k1).
 * Delegates hash-to-group to the existing {@link HashToCurve} pipeline and
 * serializes all group elements as compressed SEC1 byte arrays.
 */
public record WeierstrassGroupSpec(
    Curve curve,
    HashToCurve hashToCurveImpl,
    HashToField hashToScalarFieldImpl
) implements GroupSpec {

  private static final SecureRandom RANDOM = new SecureRandom();

  /** P-256 / SHA-256 instance (RFC 9497 §4.1). */
  public static final WeierstrassGroupSpec P256_SHA256 = buildP256();

  /** P-384 / SHA-384 instance (RFC 9497 §4.2). */
  public static final WeierstrassGroupSpec P384_SHA384 = buildP384();

  /** P-521 / SHA-512 instance (RFC 9497 §4.3). */
  public static final WeierstrassGroupSpec P521_SHA512 = buildP521();

  /** secp256k1 instance (used in RFC 9380 tests). */
  public static WeierstrassGroupSpec forSecp256k1() {
    return buildSecp256k1();
  }

  @Override
  public BigInteger groupOrder() {
    return curve.n();
  }

  @Override
  public int elementSize() {
    // Compressed SEC1: 1 prefix byte + ceil(fieldBits / 8) field bytes.
    int fieldBytes = (curve.curve().getFieldSize() + 7) / 8;
    return 1 + fieldBytes;
  }

  @Override
  public byte[] hashToGroup(byte[] msg, byte[] dst) {
    return hashToCurveImpl.hashToCurve(msg, dst).getEncoded(true);
  }

  @Override
  public BigInteger hashToScalar(byte[] msg, byte[] dst) {
    return hashToScalarFieldImpl.hashToField(msg, dst, 1)[0];
  }

  @Override
  public byte[] scalarMultiply(BigInteger scalar, byte[] element) {
    ECPoint p = deserializePoint(element);
    return p.multiply(scalar).normalize().getEncoded(true);
  }

  @Override
  public byte[] scalarMultiplyGenerator(BigInteger scalar) {
    return curve.g().multiply(scalar).normalize().getEncoded(true);
  }

  @Override
  public BigInteger randomScalar() {
    BigInteger n = curve.n();
    BigInteger k;
    do {
      k = new BigInteger(n.bitLength(), RANDOM);
    } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(n) >= 0);
    return k;
  }

  @Override
  public byte[] serializeScalar(BigInteger k) {
    int ns = (curve.n().bitLength() + 7) / 8;
    byte[] raw = k.toByteArray();
    if (raw.length == ns) {
      return raw.clone();
    }
    if (raw.length > ns) {
      // Strip BigInteger sign byte (leading zero for non-negative with high bit set).
      byte[] trimmed = new byte[ns];
      System.arraycopy(raw, raw.length - ns, trimmed, 0, ns);
      return trimmed;
    }
    // Pad with leading zeros.
    byte[] padded = new byte[ns];
    System.arraycopy(raw, 0, padded, ns - raw.length, raw.length);
    return padded;
  }

  /**
   * Deserializes a compressed SEC1 byte array to an EC point.
   * Validates the point is on the curve and not the identity element to prevent
   * invalid-curve and small-subgroup attacks.
   */
  public ECPoint deserializePoint(byte[] bytes) {
    ECPoint p = curve.params().getCurve().decodePoint(bytes);
    if (p.isInfinity()) {
      throw new SecurityException("Invalid EC point: identity element not allowed");
    }
    if (!p.isValid()) {
      throw new SecurityException("Invalid EC point: not on curve or wrong subgroup");
    }
    return p;
  }

  // ─── Builders ────────────────────────────────────────────────────────────────

  private static WeierstrassGroupSpec buildP256() {
    return new WeierstrassGroupSpec(
        Curve.P256_CURVE,
        HashToCurve.forP256(),
        HashToField.forP256Scalar()
    );
  }

  private static WeierstrassGroupSpec buildP384() {
    return new WeierstrassGroupSpec(
        Curve.P384_CURVE,
        HashToCurve.forP384(),
        HashToField.forP384Scalar()
    );
  }

  private static WeierstrassGroupSpec buildP521() {
    return new WeierstrassGroupSpec(
        Curve.P521_CURVE,
        HashToCurve.forP521(),
        HashToField.forP521Scalar()
    );
  }

  private static WeierstrassGroupSpec buildSecp256k1() {
    // secp256k1 is used in RFC 9380 hash-to-curve tests only (not in OPRF).
    // hashToScalarFieldImpl uses the base field; scalar-field operations are not needed.
    return new WeierstrassGroupSpec(
        Curve.SECP256K1_CURVE,
        HashToCurve.forSecp256k1(),
        HashToField.forSecp256k1()
    );
  }
}
