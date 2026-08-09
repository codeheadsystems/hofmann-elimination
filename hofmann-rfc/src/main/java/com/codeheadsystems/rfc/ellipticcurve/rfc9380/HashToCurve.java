package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * RFC 9380 compliant hash-to-curve implementation.
 * <p>
 * Supports both secp256k1 (via 3-isogeny) and P-256 (direct SWU, no isogeny).
 * <p>
 * The implementation follows the complete hash_to_curve flow from RFC 9380 Section 3:
 * 1. hash_to_field: Convert message to two field elements using SHA-256 expansion
 * 2. map_to_curve: For each field element, apply Simplified SWU (plus isogeny for secp256k1)
 * 3. Point addition: Add the two mapped points
 * 4. clear_cofactor: No-op (h_eff = 1 for both secp256k1 and P-256)
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9380.html">RFC 9380</a>
 */
public class HashToCurve {

  /**
   * The RFC 9380 §8.7 suite ID for secp256k1 random-oracle encoding.
   *
   * <p><strong>This is a secp256k1 tag, and this class also serves P-256, P-384 and P-521.</strong>
   * It is named for the suite it belongs to rather than "default" because
   * {@code forP521().hashToCurve(msg, DEFAULT_DST)} compiles, runs, and produces output that is
   * wrong in the way that matters least visibly: it is a perfectly good hash, it round-trips, and
   * it silently disagrees with every conformant implementation of P-521 — including this
   * library's own other entry points. RFC 9380 §3.1 requires the DST to identify the suite, which
   * is exactly the mistake the old name invited.
   *
   * <p>Applications should pass their own application-specific DST. Callers that want the
   * conformant per-suite tag should take it from the cipher suite rather than from here.
   */
  public static final String SECP256K1_XMD_SHA256_SSWU_RO_DST = "secp256k1_XMD:SHA-256_SSWU_RO_";

  /**
   * Old name for {@link #SECP256K1_XMD_SHA256_SSWU_RO_DST}.
   *
   * @deprecated the name says "default" but the value is specific to secp256k1. Use
   *     {@link #SECP256K1_XMD_SHA256_SSWU_RO_DST} when that is the curve in use, and a
   *     suite-appropriate tag otherwise.
   */
  @Deprecated(since = "3.2.0", forRemoval = true)
  public static final String DEFAULT_DST = SECP256K1_XMD_SHA256_SSWU_RO_DST;

  private final HashToField hashToField;
  private final SimplifiedSWU simplifiedSWU;
  private final IsogenyMap isogenyMap;
  private final ECCurve targetCurve; // used when isogenyMap == null (e.g. P-256)

  /**
   * Creates a HashToCurve instance with isogeny (secp256k1 style).
   *
   * @param hashToField   hash_to_field implementation
   * @param simplifiedSWU Simplified SWU mapping
   * @param isogenyMap    isogeny map to target curve
   */
  private HashToCurve(HashToField hashToField, SimplifiedSWU simplifiedSWU, IsogenyMap isogenyMap) {
    this.hashToField = hashToField;
    this.simplifiedSWU = simplifiedSWU;
    this.isogenyMap = isogenyMap;
    this.targetCurve = null;
  }

  /**
   * Creates a HashToCurve instance without isogeny (P-256 style, direct SWU).
   *
   * @param hashToField   hash_to_field implementation
   * @param simplifiedSWU Simplified SWU mapping
   * @param targetCurve   target curve for direct point creation
   */
  private HashToCurve(HashToField hashToField, SimplifiedSWU simplifiedSWU, ECCurve targetCurve) {
    this.hashToField = hashToField;
    this.simplifiedSWU = simplifiedSWU;
    this.isogenyMap = null;
    this.targetCurve = targetCurve;
  }

  /**
   * Factory method to create a HashToCurve instance for secp256k1.
   * Uses the standard parameters from RFC 9380 Section 8.7.
   *
   * @return HashToCurve instance configured for secp256k1_XMD:SHA-256_SSWU_RO_
   */
  public static HashToCurve forSecp256k1() {
    HashToField hashToField = HashToField.forSecp256k1();
    SimplifiedSWU simplifiedSWU = SimplifiedSWU.forSecp256k1();
    IsogenyMap isogenyMap = IsogenyMap.forSecp256k1();

    return new HashToCurve(hashToField, simplifiedSWU, isogenyMap);
  }

  /**
   * Factory method to create a HashToCurve instance for P-256.
   * Uses the standard parameters from RFC 9380 Section 8.2.
   * No isogeny is needed since P-256 has A != 0.
   *
   * @return HashToCurve instance configured for P256_XMD:SHA-256_SSWU_RO_
   */
  public static HashToCurve forP256() {
    HashToField hashToField = HashToField.forP256();
    SimplifiedSWU simplifiedSWU = SimplifiedSWU.forP256();

    return new HashToCurve(hashToField, simplifiedSWU, Curve.P256_CURVE.curve());
  }

  /**
   * Factory method to create a HashToCurve instance for P-384.
   * Uses the standard parameters from RFC 9380 Section 8.3.
   * No isogeny is needed since P-384 has A != 0.
   *
   * @return HashToCurve instance configured for P384_XMD:SHA-384_SSWU_RO_
   */
  public static HashToCurve forP384() {
    HashToField hashToField = HashToField.forP384();
    SimplifiedSWU simplifiedSWU = SimplifiedSWU.forP384();
    return new HashToCurve(hashToField, simplifiedSWU, Curve.P384_CURVE.curve());
  }

  /**
   * Factory method to create a HashToCurve instance for P-521.
   * Uses the standard parameters from RFC 9380 Section 8.4.
   * No isogeny is needed since P-521 has A != 0.
   *
   * @return HashToCurve instance configured for P521_XMD:SHA-512_SSWU_RO_
   */
  public static HashToCurve forP521() {
    HashToField hashToField = HashToField.forP521();
    SimplifiedSWU simplifiedSWU = SimplifiedSWU.forP521();
    return new HashToCurve(hashToField, simplifiedSWU, Curve.P521_CURVE.curve());
  }

  /**
   * Hashes a message to a point on the curve (uniform encoding, random oracle).
   *
   * @param message Message to hash
   * @param dst     Domain Separation Tag (should be application-specific)
   * @return Point on the curve that is uniformly distributed
   */
  public ECPoint hashToCurve(byte[] message, byte[] dst) {
    // Step 1: hash_to_field - produce two field elements
    BigInteger[] fieldElements = hashToField.hashToField(message, dst, 2);
    BigInteger u0 = fieldElements[0];
    BigInteger u1 = fieldElements[1];

    // Step 2: map_to_curve for each field element
    BigInteger[] swu0 = simplifiedSWU.map(u0);
    BigInteger[] swu1 = simplifiedSWU.map(u1);

    ECPoint Q0;
    ECPoint Q1;
    if (isogenyMap != null) {
      Q0 = isogenyMap.map(swu0);
      Q1 = isogenyMap.map(swu1);
    } else if (targetCurve != null) {
      Q0 = targetCurve.createPoint(swu0[0], swu0[1]);
      Q1 = targetCurve.createPoint(swu1[0], swu1[1]);
    } else {
      // Unreachable: the two private constructors guarantee exactly one is non-null.
      throw new IllegalStateException("HashToCurve: both isogenyMap and targetCurve are null");
    }

    // Step 3: Add the two points
    ECPoint R = Q0.add(Q1).normalize();

    // Step 4: clear_cofactor (h_eff = 1 for both secp256k1 and P-256, no-op)
    if (R.isInfinity()) {
      throw new ArithmeticException("hash_to_curve produced identity element — check DST");
    }
    return R;
  }

  /**
   * Convenience method using byte array message and string DST.
   *
   * @param message Message to hash
   * @param dst     Domain Separation Tag as string
   * @return Point on the curve
   */
  public ECPoint hashToCurve(byte[] message, String dst) {
    return hashToCurve(message, dst.getBytes(StandardCharsets.UTF_8));
  }
}
