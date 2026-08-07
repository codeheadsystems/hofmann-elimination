package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import com.codeheadsystems.rfc.common.ByteUtils;
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

  /**
   * Multiplier used for every secret-scalar multiplication on this curve.
   * <p>
   * {@code ECPoint.multiply} would otherwise use the curve's default, which for the NIST prime
   * curves (no GLV endomorphism) is BouncyCastle's {@code WNafL2RMultiplier}. Window-NAF leaks
   * the scalar three ways: the add/double sequence depends on its digits, the precomputed table
   * is indexed by secret values, and the window size is chosen from its bit length. A measured
   * ~12% timing separation between low- and high-Hamming-weight scalars of equal bit length was
   * reproducible on this curve.
   * <p>
   * Every scalar reaching {@link #scalarMultiply} is secret: the server's long-term OPRF key, the
   * per-credential OPRF key, the server's long-term and ephemeral AKE keys, the client's blind,
   * and the client's recovered private key. The server-side OPRF evaluation is the sharpest
   * target — the attacker supplies the point, so BouncyCastle's per-point precomputation cache
   * misses on every request and the signal stays clean, and evaluations against a long-lived key
   * can be requested without limit.
   * <p>
   * The Montgomery ladder performs one add and one double per bit in a fixed order with no
   * secret-indexed lookups, removing all three leaks above. It is slower — roughly 2x — which is
   * the intended trade on a path that handles long-term key material.
   */
  @Override
  public byte[] scalarMultiply(BigInteger scalar, byte[] element) {
    ECPoint p = deserializePoint(element);
    return ladderMultiply(p, scalar).normalize().getEncoded(true);
  }

  /**
   * Montgomery ladder over BouncyCastle's point arithmetic.
   * <p>
   * Written out rather than configured because BouncyCastle 1.85 no longer ships
   * {@code MontgomeryLadderMultiplier} — the multipliers it exposes are {@code WNafL2RMultiplier},
   * {@code GLVMultiplier}, {@code FixedPointCombMultiplier} and {@code WTauNafMultiplier}, none of
   * which is suitable for a secret scalar on a curve without an endomorphism.
   * <p>
   * Each iteration performs exactly one addition and one doubling, and which of the two
   * accumulators receives which is selected by indexing rather than by branching to different
   * code. The scalar is reduced modulo the group order first and the loop runs a fixed
   * {@code n.bitLength()} iterations, so the iteration count does not depend on the key's
   * magnitude.
   * <p>
   * The scalar is first rescaled to a fixed width by {@link #fixedWidthScalar}, so the loop runs
   * exactly {@code n.bitLength() + 1} iterations with the top bit always set. Without that, a
   * scalar with leading zeros would spend its first iterations operating on the point at
   * infinity, where BouncyCastle short-circuits the addition — measurably cheaper, and therefore
   * a channel revealing the position of the leading set bit. Measured before rescaling: a
   * 128-bit scalar ran 48% faster than a 256-bit one on P-256.
   * <p>
   * <strong>Residual, stated rather than glossed:</strong> this is still not constant-time in the
   * strict sense. The two-element accumulator array is indexed by a secret bit — a far smaller
   * cache-footprint target than wNAF's precomputed table, and both references share a cache line,
   * but the access pattern to the two heap objects remains observable to a co-located attacker
   * using cache probing. Eliminating that needs field-level constant-time primitives BouncyCastle
   * does not expose.
   *
   * @param p      the base point, already validated by {@link #deserializePoint}
   * @param scalar the secret scalar
   * @return {@code scalar · p}
   */
  private ECPoint ladderMultiply(final ECPoint p, final BigInteger scalar) {
    BigInteger n = curve.n();
    BigInteger k = fixedWidthScalar(scalar, n);
    // r[0] accumulates the result, r[1] trails it by one multiple of p. The loop maintains the
    // invariant r[1] = r[0] + p, which is what lets every step do one add and one double
    // regardless of the bit.
    ECPoint[] r = new ECPoint[]{curve.params().getCurve().getInfinity(), p};
    for (int i = n.bitLength(); i >= 0; i--) {
      int bit = k.testBit(i) ? 1 : 0;
      int other = 1 - bit;
      r[other] = r[other].add(r[bit]);
      r[bit] = r[bit].twice();
    }
    return r[0];
  }

  /**
   * Rescales a scalar to exactly {@code n.bitLength() + 1} bits without changing the result of
   * multiplying a prime-order point by it.
   * <p>
   * Adding the group order is free arithmetically — {@code n·P = O} for any point of order n, so
   * {@code (k + n)·P = k·P} — but it does change the bit length, which is the point. Reduce, then
   * add {@code n} once; that lands on either {@code L} or {@code L+1} bits, and adding {@code n}
   * a second time in the first case always lands on {@code L+1}. Since {@code n ∈ [2^(L-1), 2^L)},
   * {@code k + 2n < 2^L + n < 2^(L+1)} and {@code k + 2n ≥ 2n ≥ 2^L}, so the result has exactly
   * {@code L+1} bits with the top bit set — making the ladder's iteration count and its
   * infinity-short-circuit behaviour independent of the secret.
   *
   * @param scalar the secret scalar, any magnitude or sign
   * @param n      the group order
   * @return an equivalent scalar of exactly {@code n.bitLength() + 1} bits
   */
  static BigInteger fixedWidthScalar(final BigInteger scalar, final BigInteger n) {
    BigInteger k = scalar.mod(n).add(n);
    if (k.bitLength() == n.bitLength()) {
      k = k.add(n);
    }
    return k;
  }

  /**
   * Uses the same ladder as {@link #scalarMultiply}. The base point being fixed and public does
   * not make the scalar public: this path carries the server's ephemeral AKE key on every
   * authentication, the client's ephemeral AKE key, the long-term server key at generation, and
   * — the sharpest case — the client's long-term private key, which {@code OpaqueEnvelope.recover}
   * recomputes from the same secret value on every single authentication.
   * <p>
   * BouncyCastle resolves the generator path to {@code WNafL2RMultiplier} for all three NIST
   * curves (and {@code GLVMultiplier} for secp256k1), not to a comb multiplier, so before this it
   * leaked the same way {@link #scalarMultiply} did — a measured ~13% Hamming-weight signal at
   * equal bit length. The precomputed table is cached for the fixed generator, which makes the
   * leak cleaner to measure rather than smaller: the table lookups are still indexed by secret
   * digits and the add/double sequence still follows them.
   */
  @Override
  public byte[] scalarMultiplyGenerator(BigInteger scalar) {
    return ladderMultiply(curve.g(), scalar).normalize().getEncoded(true);
  }

  @Override
  public byte[] serializeScalar(BigInteger k) {
    if (k.signum() < 0 || k.compareTo(curve.n()) >= 0) {
      throw new IllegalArgumentException("Scalar out of range [0, n-1]");
    }
    return ByteUtils.scalarToFixedBytes(k, scalarSize());
  }

  @Override
  public int scalarSize() {
    return (curve.n().bitLength() + 7) / 8;
  }

  @Override
  public BigInteger deserializeScalar(byte[] bytes) {
    if (bytes == null || bytes.length != scalarSize()) {
      throw new IllegalArgumentException(
          "Scalar encoding must be exactly " + scalarSize() + " bytes");
    }
    BigInteger k = new BigInteger(1, bytes);
    if (k.compareTo(curve.n()) >= 0) {
      throw new IllegalArgumentException("Scalar encoding is not canonical: value >= group order");
    }
    return k;
  }

  @Override
  public byte[] generator() {
    return curve.g().getEncoded(true);
  }

  /**
   * {@inheritDoc}
   * <p>
   * The length check is the substantive part. BouncyCastle's {@code decodePoint} accepts SEC1
   * uncompressed ({@code 0x04}, 65 bytes on P-256) and hybrid ({@code 0x06}/{@code 0x07}) forms
   * alongside the compressed one, but RFC 9497 §4.3-§4.5 specify deserialization as "attempting to
   * deserialize a 33-byte input string ... using the compressed Octet-String-to-Elliptic-Curve-Point
   * method". Accepting a wider set is not merely lax: the proof transcripts hash the element
   * <em>bytes</em>, so an attacker who re-encodes a client's blinded element in flight from
   * compressed to uncompressed leaves the server proving over bytes the client never sent. The
   * composite coefficients differ, verification fails, and the client sees an apparently
   * misbehaving server with no way to attribute it to a network attacker — a silent, unattributable
   * denial of service against every verifiable exchange. A public key configured in uncompressed
   * form would fail the same way, permanently.
   * <p>
   * The check lives here rather than in {@link #deserializePoint} deliberately. That method is on
   * the OPAQUE and base-mode OPRF paths, where a non-canonical encoding is harmless — no transcript
   * hashes the bytes, so the output is identical either way — and tightening it there is a wider
   * behaviour change than this commit should carry.
   */
  @Override
  public void validateElement(byte[] element) {
    if (element == null || element.length != elementSize()) {
      throw new IllegalArgumentException(
          "Element encoding must be exactly " + elementSize() + " bytes (compressed SEC1), got "
              + (element == null ? "null" : element.length));
    }
    deserializePoint(element);
  }

  @Override
  public byte[] add(byte[] a, byte[] b) {
    ECPoint sum = deserializePoint(a).add(deserializePoint(b)).normalize();
    if (sum.isInfinity()) {
      throw new IdentityResultException("Element addition produced the identity element");
    }
    return sum.getEncoded(true);
  }

  @Override
  public byte[] linearCombinationSecret(BigInteger[] scalars, byte[][] elements) {
    return linearCombination(scalars, elements, true);
  }

  @Override
  public byte[] linearCombinationPublic(BigInteger[] scalars, byte[][] elements) {
    return linearCombination(scalars, elements, false);
  }

  /**
   * Accumulates {@code sum(scalars[i] * elements[i])} entirely in {@link ECPoint} form.
   * <p>
   * The accumulator starts at infinity and individual terms may be infinity (a zero scalar
   * produces one, and a remote party controls {@code s} and {@code c} in a proof), so nothing here
   * may round-trip through {@link #deserializePoint}, which rejects infinity. Only the final sum
   * is serialized, and only after it has been shown not to be the identity.
   *
   * @param secret whether the scalars require the constant-time ladder
   */
  private byte[] linearCombination(BigInteger[] scalars, byte[][] elements, boolean secret) {
    if (scalars == null || elements == null) {
      throw new IllegalArgumentException("Scalars and elements are required");
    }
    if (scalars.length != elements.length) {
      throw new IllegalArgumentException(
          "Scalar and element counts differ: " + scalars.length + " vs " + elements.length);
    }
    if (scalars.length == 0) {
      throw new IllegalArgumentException("Linear combination requires at least one term");
    }
    ECPoint acc = curve.params().getCurve().getInfinity();
    for (int i = 0; i < scalars.length; i++) {
      // deserializePoint still validates each *input* element — on-curve, non-identity,
      // prime-order. Only the products and the running sum are allowed to be the identity.
      ECPoint p = deserializePoint(elements[i]);
      ECPoint term = secret
          ? ladderMultiply(p, scalars[i])
          : p.multiply(scalars[i].mod(curve.n()));
      acc = acc.add(term);
    }
    acc = acc.normalize();
    if (acc.isInfinity()) {
      throw new IdentityResultException("Linear combination produced the identity element");
    }
    return acc.getEncoded(true);
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
