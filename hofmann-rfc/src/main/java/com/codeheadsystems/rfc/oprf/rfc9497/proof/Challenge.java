package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * The challenge transcript shared by RFC 9497 §2.2.1 {@code GenerateProof} and §2.2.2
 * {@code VerifyProof}.
 * <p>
 * Factored out precisely because the two must agree byte for byte. A prover and verifier that
 * built the transcript separately could drift — a reordered field, a missing length prefix — and
 * still interoperate with each other, so the divergence would only ever surface against the RFC
 * vectors.
 * <p>
 * Note what is <em>not</em> in the transcript: {@code A}, the generator. Binding comes instead
 * from the verifier recomputing {@code t2 = s*A + c*B} with its own {@code A}, which is why both
 * sides can hardcode the generator rather than passing it.
 */
final class Challenge {

  private static final byte[] CHALLENGE_LABEL = "Challenge".getBytes(StandardCharsets.UTF_8);

  private Challenge() {
  }

  /**
   * Computes {@code c = HashToScalar(I2OSP(len(Bm),2) || Bm || ... || "Challenge")}.
   * <p>
   * The hash-to-scalar uses the ordinary suite DST, {@code "HashToScalar-" || contextString} —
   * there is no proof-specific tag. Mode separation is already carried by {@code contextString}.
   *
   * @param suite      the cipher suite
   * @param b          the serialized public key being proven against
   * @param composites the folded batch
   * @param t2         the first commitment
   * @param t3         the second commitment
   * @return the challenge scalar
   */
  static BigInteger compute(final OprfCipherSuite suite,
                            final byte[] b,
                            final Composites.Pair composites,
                            final byte[] t2,
                            final byte[] t3) {
    byte[] transcript = ByteUtils.concat(
        ByteUtils.I2OSP(b.length, 2), b,
        ByteUtils.I2OSP(composites.m().length, 2), composites.m(),
        ByteUtils.I2OSP(composites.z().length, 2), composites.z(),
        ByteUtils.I2OSP(t2.length, 2), t2,
        ByteUtils.I2OSP(t3.length, 2), t3,
        CHALLENGE_LABEL);
    return suite.hashToScalar(transcript, suite.hashToScalarDst());
  }
}
