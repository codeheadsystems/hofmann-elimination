package com.codeheadsystems.hofmann.rfc9380;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * RFC 9380 compliant hash-to-curve implementation for secp256k1.
 * <p>
 * Implements the secp256k1_XMD:SHA-256_SSWU_RO_ cipher suite which provides
 * uniform encoding (random oracle) of arbitrary byte strings to points on secp256k1.
 * <p>
 * The implementation follows the complete hash_to_curve flow from RFC 9380 Section 3:
 * 1. hash_to_field: Convert message to two field elements using SHA-256 expansion
 * 2. map_to_curve: For each field element, apply Simplified SWU then 3-isogeny to get a point on secp256k1
 * 3. Point addition: Add the two mapped points on secp256k1
 * 4. clear_cofactor: No-op for secp256k1 (h_eff = 1)
 * <p>
 * This provides the cryptographic properties needed for OPRF-like protocols.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9380.html">RFC 9380</a>
 */
public class HashToCurve {

  /**
   * Default domain separation tag for secp256k1 random oracle encoding.
   * Applications should use their own application-specific DST.
   */
  public static final String DEFAULT_DST = "secp256k1_XMD:SHA-256_SSWU_RO_";

  private final HashToField hashToField;
  private final SimplifiedSWU simplifiedSWU;
  private final IsogenyMap isogenyMap;

  /**
   * Creates a HashToCurve instance with the given components.
   *
   * @param hashToField   hash_to_field implementation
   * @param simplifiedSWU Simplified SWU mapping
   * @param isogenyMap    3-isogeny map to target curve
   */
  public HashToCurve(HashToField hashToField, SimplifiedSWU simplifiedSWU, IsogenyMap isogenyMap) {
    this.hashToField = hashToField;
    this.simplifiedSWU = simplifiedSWU;
    this.isogenyMap = isogenyMap;
  }

  /**
   * Hashes a message to a point on the curve (uniform encoding, random oracle).
   * <p>
   * This is the main entry point for the hash_to_curve operation.
   * It produces a uniformly random point on the curve given an arbitrary input message.
   *
   * @param message Message to hash
   * @param dst     Domain Separation Tag (should be application-specific)
   * @return Point on secp256k1 that is uniformly distributed
   */
  public ECPoint hashToCurve(byte[] message, byte[] dst) {
    // Step 1: hash_to_field - produce two field elements
    BigInteger[] fieldElements = hashToField.hashToField(message, dst, 2);
    BigInteger u0 = fieldElements[0];
    BigInteger u1 = fieldElements[1];

    // Step 2: map_to_curve (SWU + isogeny) for each field element
    BigInteger[] swu0 = simplifiedSWU.map(u0);
    ECPoint Q0 = isogenyMap.map(swu0);

    BigInteger[] swu1 = simplifiedSWU.map(u1);
    ECPoint Q1 = isogenyMap.map(swu1);

    // Step 3: Add the two points on secp256k1
    ECPoint R = Q0.add(Q1).normalize();

    // Step 4: clear_cofactor (h_eff = 1 for secp256k1, so this is a no-op)
    return R;
  }

  /**
   * Convenience method using byte array message and string DST.
   *
   * @param message Message to hash
   * @param dst     Domain Separation Tag as string
   * @return Point on secp256k1
   */
  public ECPoint hashToCurve(byte[] message, String dst) {
    return hashToCurve(message, dst.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Factory method to create a HashToCurve instance for secp256k1.
   * Uses the standard parameters from RFC 9380 Section 8.7.
   *
   * @param domainParams secp256k1 domain parameters
   * @return HashToCurve instance configured for secp256k1_XMD:SHA-256_SSWU_RO_
   */
  public static HashToCurve forSecp256k1(ECDomainParameters domainParams) {
    HashToField hashToField = HashToField.forSecp256k1();
    SimplifiedSWU simplifiedSWU = SimplifiedSWU.forSecp256k1(domainParams);
    IsogenyMap isogenyMap = IsogenyMap.forSecp256k1(domainParams.getCurve());

    return new HashToCurve(hashToField, simplifiedSWU, isogenyMap);
  }

  /**
   * Convenience method to hash directly using secp256k1 with default DST.
   * <p>
   * Note: For production use, applications should use their own application-specific DST
   * rather than the default.
   *
   * @param message      Message to hash
   * @param domainParams secp256k1 domain parameters
   * @return Point on secp256k1
   */
  public static ECPoint hash(byte[] message, ECDomainParameters domainParams) {
    return forSecp256k1(domainParams).hashToCurve(message, DEFAULT_DST);
  }

  /**
   * Convenience method with custom DST.
   *
   * @param message      Message to hash
   * @param dst          Application-specific domain separation tag
   * @param domainParams secp256k1 domain parameters
   * @return Point on secp256k1
   */
  public static ECPoint hash(byte[] message, String dst, ECDomainParameters domainParams) {
    return forSecp256k1(domainParams).hashToCurve(message, dst);
  }
}
