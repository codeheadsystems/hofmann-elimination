package com.codeheadsystems.ellipticcurve.rfc9380;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

/**
 * Abstraction over a cryptographic group for use in RFC 9497 OPRF.
 * <p>
 * Implementations bundle all per-group details (curve/field arithmetic, hash-to-group,
 * serialization) into one class, so adding a new cipher suite only requires implementing
 * this interface.
 * <p>
 * All group elements cross the interface as {@code byte[]} (serialized canonical form).
 */
public interface GroupSpec {

  /**
   * Serializes an EC point to a compressed hex string.
   */
  default String toHex(final ECPoint point) {
    if (point == null) {
      throw new IllegalArgumentException("EC point must not be null");
    }
    return Hex.toHexString(point.getEncoded(true));
  }

  /**
   * Deserializes a compressed hex string to an EC point on this group's curve.
   * Validates the point is on the curve and not the identity element to prevent
   * invalid-curve and small-subgroup attacks.
   */
  ECPoint toEcPoint(String hex);

  /** The prime group order n (also used as the scalar modulus). */
  BigInteger groupOrder();

  /** Size of a serialized group element in bytes (Ne). */
  int elementSize();

  /**
   * Maps a message to a group element using the suite's hash-to-group algorithm.
   *
   * @param msg message bytes
   * @param dst domain separation tag
   * @return serialized group element (Ne bytes)
   */
  byte[] hashToGroup(byte[] msg, byte[] dst);

  /**
   * Maps a message to a scalar in [0, n-1] using the suite's hash-to-scalar algorithm.
   *
   * @param msg message bytes
   * @param dst domain separation tag
   * @return scalar modulo group order
   */
  BigInteger hashToScalar(byte[] msg, byte[] dst);

  /**
   * Multiplies a serialized group element by a scalar.
   * Performs point validation before the operation.
   *
   * @param scalar  scalar multiplier
   * @param element serialized group element
   * @return serialized result element
   */
  byte[] scalarMultiply(BigInteger scalar, byte[] element);

  /**
   * Multiplies the group generator G by a scalar.
   *
   * @param scalar scalar multiplier
   * @return serialized result element
   */
  byte[] scalarMultiplyGenerator(BigInteger scalar);

  /**
   * Serializes a scalar to a fixed-size big-endian byte array (Ns bytes).
   *
   * @param k scalar value in [0, n-1]
   * @return Ns-byte big-endian encoding
   */
  byte[] serializeScalar(BigInteger k);
}
