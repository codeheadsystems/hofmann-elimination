package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;

/**
 * Implementation of hash_to_field from RFC 9380 Section 5.3.
 * <p>
 * Converts an arbitrary byte string to one or more field elements
 * in a prime field Fp using expand_message_xmd.
 */
public class HashToField {

  private final BigInteger p; // Prime field modulus
  private final int L; // Length parameter in bytes
  private final int m; // Extension degree (1 for prime fields)
  private final ExpandMessageXmd xmd;

  /**
   * Creates a HashToField instance for a specific prime field.
   *
   * @param p   Prime field modulus
   * @param L   Length parameter
   * @param xmd ExpandMessageXmd instance (determines hash algorithm)
   */
  private HashToField(BigInteger p, int L, ExpandMessageXmd xmd) {
    this.p = p;
    this.L = L;
    this.m = 1; // prime field, not an extension field
    this.xmd = xmd;
  }

  /**
   * Factory method for secp256k1 field parameters.
   * L = 48, SHA-256.
   */
  public static HashToField forSecp256k1() {
    BigInteger p = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    );
    return new HashToField(p, 48, ExpandMessageXmd.forSha256());
  }

  /**
   * Factory method for P-256 base field parameters.
   * L = 48, SHA-256.
   */
  public static HashToField forP256() {
    BigInteger p = Curve.P256_CURVE.curve().getField().getCharacteristic();
    return new HashToField(p, 48, ExpandMessageXmd.forSha256());
  }

  /**
   * Factory method for P-256 scalar field parameters (group order as modulus).
   * L = 48, SHA-256.
   */
  public static HashToField forP256Scalar() {
    return new HashToField(Curve.P256_CURVE.n(), 48, ExpandMessageXmd.forSha256());
  }

  /**
   * Factory method for P-384 base field parameters.
   * L = 72, SHA-384.
   */
  public static HashToField forP384() {
    BigInteger p = Curve.P384_CURVE.curve().getField().getCharacteristic();
    return new HashToField(p, 72, ExpandMessageXmd.forSha384());
  }

  /**
   * Factory method for P-384 scalar field parameters (group order as modulus).
   * L = 72, SHA-384.
   */
  public static HashToField forP384Scalar() {
    return new HashToField(Curve.P384_CURVE.n(), 72, ExpandMessageXmd.forSha384());
  }

  /**
   * Factory method for P-521 base field parameters.
   * L = 98, SHA-512.
   */
  public static HashToField forP521() {
    BigInteger p = Curve.P521_CURVE.curve().getField().getCharacteristic();
    return new HashToField(p, 98, ExpandMessageXmd.forSha512());
  }

  /**
   * Factory method for P-521 scalar field parameters (group order as modulus).
   * L = 98, SHA-512.
   */
  public static HashToField forP521Scalar() {
    return new HashToField(Curve.P521_CURVE.n(), 98, ExpandMessageXmd.forSha512());
  }

  /**
   * Hashes a message to one or more field elements.
   *
   * @param msg   The message to hash
   * @param dst   Domain Separation Tag
   * @param count Number of field elements to produce (typically 2 for uniform encoding)
   * @return Array of field elements in Fp
   */
  public BigInteger[] hashToField(byte[] msg, byte[] dst, int count) {
    if (count <= 0) {
      throw new IllegalArgumentException("count must be positive");
    }

    int lenInBytes = count * m * L;

    byte[] uniformBytes = xmd.expand(msg, dst, lenInBytes);

    // Convert uniform_bytes to field elements
    BigInteger[] fieldElements = new BigInteger[count];

    for (int i = 0; i < count; i++) {
      int elmOffset = L * i * m;

      // tv = substr(uniform_bytes, elm_offset, L)
      byte[] tv = new byte[L];
      System.arraycopy(uniformBytes, elmOffset, tv, 0, L);

      // e_i = OS2IP(tv) mod p
      BigInteger element = os2ip(tv).mod(p);
      fieldElements[i] = element;
    }

    return fieldElements;
  }

  /**
   * Octet String to Integer Primitive (OS2IP) from RFC 8017.
   * Converts an octet string to a non-negative integer.
   */
  private BigInteger os2ip(byte[] octets) {
    return new BigInteger(1, octets); // 1 means positive
  }
}
