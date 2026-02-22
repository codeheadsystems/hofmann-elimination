package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * {@link GroupSpec} implementation for Weierstrass elliptic curves (P-256, P-384, P-521, secp256k1).
 * Delegates hash-to-group to the existing {@link HashToCurve} pipeline and
 * serializes all group elements as compressed SEC1 byte arrays.
 */
public record WeierstrassGroupSpecImpl(
    Curve curve,
    HashToCurve hashToCurveImpl,
    HashToField hashToScalarFieldImpl
) implements GroupSpec {

  /**
   * P-256 / SHA-256 instance (RFC 9497 §4.1).
   */
  public static final WeierstrassGroupSpecImpl P256_SHA256 = buildP256();

  /**
   * P-384 / SHA-384 instance (RFC 9497 §4.2).
   */
  public static final WeierstrassGroupSpecImpl P384_SHA384 = buildP384();

  /**
   * P-521 / SHA-512 instance (RFC 9497 §4.3).
   */
  public static final WeierstrassGroupSpecImpl P521_SHA512 = buildP521();

  /**
   * secp256k1 instance (used in RFC 9380 tests).
   *
   * @return the weierstrass group spec
   */
  public static WeierstrassGroupSpecImpl forSecp256k1() {
    return buildSecp256k1();
  }

  private static WeierstrassGroupSpecImpl buildP256() {
    return new WeierstrassGroupSpecImpl(
        Curve.P256_CURVE,
        HashToCurve.forP256(),
        HashToField.forP256Scalar()
    );
  }

  private static WeierstrassGroupSpecImpl buildP384() {
    return new WeierstrassGroupSpecImpl(
        Curve.P384_CURVE,
        HashToCurve.forP384(),
        HashToField.forP384Scalar()
    );
  }

  private static WeierstrassGroupSpecImpl buildP521() {
    return new WeierstrassGroupSpecImpl(
        Curve.P521_CURVE,
        HashToCurve.forP521(),
        HashToField.forP521Scalar()
    );
  }

  private static WeierstrassGroupSpecImpl buildSecp256k1() {
    // secp256k1 is used in RFC 9380 hash-to-curve tests only (not in OPRF).
    // hashToScalarFieldImpl uses the base field; scalar-field operations are not needed.
    return new WeierstrassGroupSpecImpl(
        Curve.SECP256K1_CURVE,
        HashToCurve.forSecp256k1(),
        HashToField.forSecp256k1()
    );
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

  // ─── Builders ────────────────────────────────────────────────────────────────

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
  public byte[] serializeScalar(BigInteger k) {
    if (k.signum() < 0 || k.compareTo(curve.n()) >= 0) {
      throw new IllegalArgumentException("Scalar out of range [0, n-1]");
    }
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
   * Deserializes a compressed SEC1 byte array to an EC point, with full validation.
   *
   * <p>Checks performed:
   * <ol>
   *   <li><b>Non-identity</b> — rejects the point at infinity.</li>
   *   <li><b>On-curve</b> — rejects points that do not satisfy the curve equation.</li>
   *   <li><b>Prime-order subgroup</b> — for curves with cofactor h&gt;1, verifies that
   *       {@code n·P = O} where {@code n} is the group order. For all currently supported
   *       curves (P-256, P-384, P-521, secp256k1) the cofactor {@code h=1}, which means
   *       every non-identity on-curve point is automatically in the prime-order subgroup
   *       and this check is a no-op. The guard is retained for defense-in-depth should a
   *       cofactor&gt;1 curve be added in the future.</li>
   * </ol>
   */
  @Override
  public ECPoint deserializePoint(byte[] bytes) {
    ECPoint p = curve.params().getCurve().decodePoint(bytes);
    if (p.isInfinity()) {
      throw new SecurityException("Invalid EC point: identity element not allowed");
    }
    if (!p.isValid()) {
      throw new SecurityException("Invalid EC point: not on curve");
    }
    // For h=1 curves (P-256, P-384, P-521, secp256k1) every non-identity curve point is
    // in the prime-order subgroup — the check below is skipped at no security cost.
    // For h>1 curves we verify n·P = O explicitly.
    if (!curve.h().equals(BigInteger.ONE) && !p.multiply(curve.n()).isInfinity()) {
      throw new SecurityException("Invalid EC point: not in prime-order subgroup");
    }
    return p;
  }
}
