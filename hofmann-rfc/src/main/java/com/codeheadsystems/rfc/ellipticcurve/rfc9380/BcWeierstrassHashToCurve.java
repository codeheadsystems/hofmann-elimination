package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import java.math.BigInteger;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.hash2curve.CurveProcessor;
import org.bouncycastle.crypto.hash2curve.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.HashToField;
import org.bouncycastle.crypto.hash2curve.MapToCurve;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.impl.NistCurveProcessor;
import org.bouncycastle.crypto.hash2curve.impl.SimplifiedShallueVanDeWoestijneMapToCurve;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * RFC 9380 {@code hash_to_curve} for the NIST prime curves, delegating every cryptographic step to
 * BouncyCastle's {@code org.bouncycastle.crypto.hash2curve} package.
 *
 * <p>
 * This composes the three BouncyCastle pieces by hand rather than calling
 * {@code HashToEllipticCurve.getInstance(profile, dst)}. The facade binds the domain separation tag
 * at construction and accepts it only as a {@code String}, and both are wrong here:
 * </p>
 * <ul>
 *   <li><strong>The DST is bytes, not text.</strong> RFC 9497 §3.1 builds the context string as
 *   {@code "OPRFV1-" || I2OSP(mode, 1) || "-" || suiteID}, so every DST this library uses carries a
 *   raw mode byte. Those bytes happen to be 0x00–0x02 today, which survives a UTF-8 round trip
 *   intact, but a tag byte of 0x80 or above would not — it would decode to U+FFFD and re-encode to
 *   different bytes, silently changing the derived point. {@link HashToField} takes a
 *   {@code byte[]} DST, so going one level below the facade removes the question rather than
 *   relying on that invariant continuing to hold.</li>
 *   <li><strong>The DST varies per call.</strong> {@link GroupSpec#hashToGroup} takes it as a
 *   parameter, so a DST-bound instance would have to be rebuilt on every call — and the expensive
 *   part of that construction is not the DST.</li>
 * </ul>
 *
 * <p>
 * Hence the split below. The map and the curve processor are built once per curve and reused:
 * {@link SimplifiedShallueVanDeWoestijneMapToCurve}'s constructor builds a
 * {@code GenericSqrtRatioCalculator}, whose constructor performs several modular exponentiations to
 * derive the {@code sqrt_ratio} constants. Only {@link HashToField} is constructed per call, and
 * that is a handful of field assignments.
 * </p>
 *
 * <p>
 * All four collaborators are safe to share: the map, the curve processor and the message expansion
 * hold only final configuration, and {@code XmdMessageExpansion} clones its digest per invocation
 * rather than mutating the instance it was given.
 * </p>
 *
 * <p>
 * <strong>Not constant-time.</strong> BouncyCastle says so directly in {@code H2cUtils}: its
 * {@code cmov} is an ordinary ternary and the arithmetic runs on {@code BigInteger}. The
 * hand-rolled implementation this replaces made no such guarantee either, so nothing regressed —
 * but note that the message reaching {@link #hashToCurve} is the client's OPRF input, which in
 * OPAQUE is password-derived. The constant-time work in this package targets
 * {@link WeierstrassGroupSpecImpl#scalarMultiply}, where a long-lived server key meets an
 * attacker-chosen point, and is unaffected by this class.
 * </p>
 */
public final class BcWeierstrassHashToCurve {

  private final ECCurve curve;
  private final MessageExpansion messageExpansion;
  private final MapToCurve mapToCurve;
  private final CurveProcessor curveProcessor;
  private final int lengthInBytes;

  private BcWeierstrassHashToCurve(final ECCurve curve,
                                   final MessageExpansion messageExpansion,
                                   final MapToCurve mapToCurve,
                                   final CurveProcessor curveProcessor,
                                   final int lengthInBytes) {
    this.curve = curve;
    this.messageExpansion = messageExpansion;
    this.mapToCurve = mapToCurve;
    this.curveProcessor = curveProcessor;
    this.lengthInBytes = lengthInBytes;
  }

  /**
   * Builds the pipeline for one suite.
   *
   * <p>
   * The suite parameters — the SSWU {@code Z}, the per-element byte length {@code L} and the
   * security level {@code k} — are read off the BouncyCastle profile rather than restated here, so
   * there is one source for them. The curve is supplied by the caller rather than taken from the
   * profile so that points land on the same {@link ECCurve} instance the rest of
   * {@link WeierstrassGroupSpecImpl} uses for arithmetic and decoding.
   * </p>
   *
   * @param curve   the curve to produce points on
   * @param profile the BouncyCastle profile naming this RFC 9380 suite, supplying Z, L and k
   * @param digest  the suite's hash, used by {@code expand_message_xmd}
   * @return a reusable pipeline for the suite
   */
  public static BcWeierstrassHashToCurve of(final ECCurve curve,
                                            final HashToCurveProfile profile,
                                            final ExtendedDigest digest) {
    return new BcWeierstrassHashToCurve(
        curve,
        new XmdMessageExpansion(digest, profile.getK()),
        new SimplifiedShallueVanDeWoestijneMapToCurve(curve, profile.getZ()),
        new NistCurveProcessor(),
        profile.getL());
  }

  /**
   * Hashes a message to a curve point using the RFC 9380 §3 {@code hash_to_curve} (random oracle)
   * encoding.
   *
   * <p>
   * The steps mirror {@code HashToEllipticCurve.hashToCurve}: two field elements, one map each, add
   * them, clear the cofactor. Cofactor clearing is a no-op in value terms for all three NIST curves
   * (h = 1) but is retained because RFC 9380 specifies it and BouncyCastle uses it to normalise the
   * point's internal representation.
   * </p>
   *
   * @param message the message to hash
   * @param dst     the domain separation tag, used verbatim as bytes
   * @return a point on the curve, uniformly distributed in the group
   * @throws ArithmeticException      if the result is the identity element, which no honest DST and
   *                                  message should produce and which callers treat as a
   *                                  configuration error rather than a value to operate on
   * @throws IllegalArgumentException if {@code dst} exceeds 255 bytes; BouncyCastle rejects
   *                                  oversize tags rather than applying the RFC 9380 §5.3.3
   *                                  {@code H2C-OVERSIZE-DST-} rewrite
   */
  public ECPoint hashToCurve(final byte[] message, final byte[] dst) {
    final HashToField hashToField =
        new HashToField(dst, curve, messageExpansion, lengthInBytes);
    final BigInteger[][] u = hashToField.process(message, 2);
    final ECPoint q0 = mapToCurve.process(u[0][0]);
    final ECPoint q1 = mapToCurve.process(u[1][0]);
    final ECPoint r = curveProcessor.clearCofactor(curveProcessor.add(q0, q1));
    if (r.isInfinity()) {
      throw new ArithmeticException("hash_to_curve produced identity element — check DST");
    }
    return r;
  }
}
