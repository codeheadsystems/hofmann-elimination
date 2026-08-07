package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import java.math.BigInteger;

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
   * The prime group order n (also used as the scalar modulus).
   *
   * @return the big integer
   */
  BigInteger groupOrder();

  /**
   * Size of a serialized group element in bytes (Ne).
   *
   * @return the int
   */
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
   * Serializes a scalar to a fixed-size byte array (Ns bytes).
   * Encoding is suite-dependent (big-endian for Weierstrass, little-endian for ristretto255).
   *
   * @param k scalar value in [0, n-1]
   * @return Ns-byte encoding
   */
  byte[] serializeScalar(BigInteger k);

  /**
   * Size of a serialized scalar in bytes (Ns).
   *
   * @return the int
   */
  int scalarSize();

  /**
   * Inverse of {@link #serializeScalar(BigInteger)}.
   * <p>
   * Rejects any encoding that is not the canonical one for a scalar in {@code [0, n-1]}: wrong
   * length, or a value at or above the group order. Both matter once scalars cross the wire, which
   * they do for the first time in the RFC 9497 §2.2 proofs — {@code c} and {@code s} arrive from a
   * remote party. Accepting {@code k} and {@code k + n} interchangeably would make the proof
   * encoding malleable.
   *
   * @param bytes Ns-byte encoding
   * @return the scalar in [0, n-1]
   * @throws IllegalArgumentException if the encoding is the wrong length or not canonical
   */
  BigInteger deserializeScalar(byte[] bytes);

  /**
   * The serialized group generator G.
   *
   * @return serialized generator (Ne bytes)
   */
  byte[] generator();

  /**
   * Adds two group elements.
   *
   * @param a serialized element
   * @param b serialized element
   * @return serialized sum
   * @throws IdentityResultException if the sum is the identity element
   */
  byte[] add(byte[] a, byte[] b);

  /**
   * Computes {@code sum(scalars[i] * elements[i])} for scalars that are <em>secret</em>.
   * <p>
   * Intermediate sums are never serialized, which is what makes this the only usable shape for the
   * RFC 9497 §2.2 proof arithmetic: the accumulator legitimately passes through the identity (the
   * RFC's {@code ComputeComposites} starts there), and every serialized-element entry point in
   * this interface rejects the identity. Individual terms may also be the identity — a caller-
   * supplied scalar of zero produces one — so the terms must stay internal too.
   * <p>
   * Use this form only for scalars that must not leak through timing: the server's OPRF key, the
   * POPRF tweaked key {@code t = skS + m}, and the proof randomness {@code r}. Everything else in
   * the proof — the composite coefficients {@code d_i}, and the wire-supplied {@code c} and
   * {@code s} — is public and belongs in {@link #linearCombinationPublic}.
   *
   * @param scalars  the scalars, same length as {@code elements}
   * @param elements the serialized elements, at least one
   * @return the serialized sum
   * @throws IdentityResultException  if the sum is the identity element
   * @throws IllegalArgumentException if the arrays are empty or of differing length
   */
  byte[] linearCombinationSecret(BigInteger[] scalars, byte[][] elements);

  /**
   * Computes {@code sum(scalars[i] * elements[i])} for scalars that are <em>public</em>.
   * <p>
   * Same contract as {@link #linearCombinationSecret} but free to use the group's fastest
   * multiplier. On the Weierstrass curves that is roughly twice the speed of the constant-time
   * ladder, which matters here because the batch proof path performs {@code 2m} of these on
   * attacker-chosen batch sizes — putting public scalars on the ladder would double the cost of
   * the one operation a client can order in bulk, for no security benefit.
   *
   * @param scalars  the scalars, same length as {@code elements}
   * @param elements the serialized elements, at least one
   * @return the serialized sum
   * @throws IdentityResultException  if the sum is the identity element
   * @throws IllegalArgumentException if the arrays are empty or of differing length
   */
  byte[] linearCombinationPublic(BigInteger[] scalars, byte[][] elements);
}
