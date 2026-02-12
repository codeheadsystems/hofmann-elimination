package com.codeheadsystems.hofmann.rfc9380;

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

  /**
   * Creates a HashToField instance for a specific prime field.
   *
   * @param p Prime field modulus
   * @param L Length parameter (must be >= ceil((ceil(log2(p)) + k) / 8) where k is security parameter)
   */
  private HashToField(BigInteger p, int L) {
    this.p = p;
    this.L = L;
    this.m = 1; // secp256k1 is a prime field, not an extension field
  }

  /**
   * Factory method for secp256k1 field parameters.
   * <p>
   * For secp256k1:
   * - p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
   * - k = 128 (security level)
   * - L = 48 (chosen to satisfy L >= ceil((ceil(log2(p)) + k) / 8))
   *
   * @return HashToField instance configured for secp256k1
   */
  public static HashToField forSecp256k1() {
    // secp256k1 field prime
    BigInteger p = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16
    );
    // L = 48 bytes (for 128-bit security with 256-bit field)
    return new HashToField(p, 48);
  }

  /**
   * Factory method for P-256 base field parameters.
   * Used for hash_to_curve (HashToGroup) operations on P-256.
   *
   * @return HashToField instance configured for P-256 field arithmetic
   */
  public static HashToField forP256() {
    // P-256 field prime
    BigInteger p = new BigInteger(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        16
    );
    // L = 48 bytes (for 128-bit security with 256-bit field)
    return new HashToField(p, 48);
  }

  /**
   * Factory method for P-256 scalar field parameters.
   * Used for HashToScalar operations (modulus is group order n, not field prime).
   *
   * @return HashToField instance configured for P-256 group order
   */
  public static HashToField forP256Scalar() {
    // P-256 group order n
    BigInteger n = new BigInteger(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        16
    );
    // L = 48 bytes (for 128-bit security with 256-bit field)
    return new HashToField(n, 48);
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

    byte[] uniformBytes = ExpandMessageXmd.expand(msg, dst, lenInBytes);

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
