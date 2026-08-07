package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * A discrete-logarithm-equality proof: the pair {@code [c, s]} produced by RFC 9497 §2.2.1
 * {@code GenerateProof} and consumed by §2.2.2 {@code VerifyProof}.
 *
 * @param c the challenge scalar
 * @param s the response scalar
 */
public record DleqProof(BigInteger c, BigInteger s) {

  /**
   * Rejects null scalars so that a directly-constructed proof and a deserialized one carry the
   * same guarantees. Range is deliberately not checked here — the group order is not available
   * without a suite, and {@link #deserialize} already enforces canonical range on everything that
   * arrives from the wire. A caller that constructs an out-of-range scalar by hand fails closed:
   * verification serializes both challenges, and serialization rejects it.
   */
  public DleqProof {
    if (c == null || s == null) {
      throw new IllegalArgumentException("Proof scalars are required");
    }
  }

  /**
   * Serializes the proof as {@code SerializeScalar(c) || SerializeScalar(s)}, exactly
   * {@code 2 * Ns} bytes.
   * <p>
   * The order is {@code c} then {@code s}, per §2.2.1's {@code return [c, s]} and the
   * {@code Proof} field in the Appendix A vectors. Nothing in a round-trip test can catch a
   * reversal — a prover and verifier that agree on the wrong order interoperate perfectly with
   * each other — so the order is only ever pinned by the RFC vectors.
   *
   * @param suite the cipher suite supplying the scalar encoding
   * @return the serialized proof
   */
  public byte[] serialize(final OprfCipherSuite suite) {
    return ByteUtils.concat(
        suite.groupSpec().serializeScalar(c),
        suite.groupSpec().serializeScalar(s));
  }

  /**
   * Parses a proof from its wire encoding.
   * <p>
   * Both scalars go through {@code deserializeScalar}, which rejects any non-canonical encoding.
   * That is what stops a proof from being malleable: without it, {@code c} and {@code c + n} would
   * both parse to the same scalar, giving an attacker distinct byte strings that verify
   * identically.
   *
   * @param suite the cipher suite supplying the scalar encoding
   * @param bytes the serialized proof, exactly {@code 2 * Ns} bytes
   * @return the parsed proof
   * @throws IllegalArgumentException if the length is wrong or either scalar is non-canonical
   */
  public static DleqProof deserialize(final OprfCipherSuite suite, final byte[] bytes) {
    int ns = suite.scalarSize();
    if (bytes == null || bytes.length != 2 * ns) {
      throw new IllegalArgumentException(
          "Proof must be exactly " + (2 * ns) + " bytes, got "
              + (bytes == null ? "null" : bytes.length));
    }
    return new DleqProof(
        suite.groupSpec().deserializeScalar(Arrays.copyOfRange(bytes, 0, ns)),
        suite.groupSpec().deserializeScalar(Arrays.copyOfRange(bytes, ns, 2 * ns)));
  }
}
