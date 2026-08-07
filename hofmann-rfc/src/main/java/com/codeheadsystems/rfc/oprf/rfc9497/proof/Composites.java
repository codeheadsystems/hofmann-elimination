package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * RFC 9497 §2.2.1 {@code ComputeCompositesFast} and §2.2.2 {@code ComputeComposites}.
 * <p>
 * Both fold a batch of element pairs into a single pair {@code (M, Z)} so that one proof covers
 * the whole batch. The coefficients {@code d_i} are derived from a transcript that binds the
 * batch index, both elements of each pair, and — through {@code seed} — the public key being
 * proven against, which is what stops a prover from reordering, substituting or replaying entries.
 */
final class Composites {

  private static final byte[] SEED_DST_PREFIX = "Seed-".getBytes(StandardCharsets.UTF_8);
  private static final byte[] COMPOSITE_LABEL = "Composite".getBytes(StandardCharsets.UTF_8);

  /**
   * Encoding-level ceiling on the batch size. The composite transcript writes the index as
   * {@code I2OSP(i, 2)}, so indices up to 65535 encode and a batch of 65536 would in fact fit;
   * this stops one short of that deliberately, since nothing is lost and the bound is then
   * obviously safe rather than exactly-at-the-limit.
   * <p>
   * This is not a usable operational cap — a batch this size is well over a hundred thousand
   * scalar multiplications on the server. It exists to keep the transcript encodable. The policy
   * cap belongs at the manager and transport layer, where request size and tail latency are the
   * governing concerns.
   */
  static final int MAX_BATCH = 65535;

  private Composites() {
  }

  /**
   * The folded batch.
   *
   * @param m the composite of the first element list
   * @param z the composite of the second element list
   */
  record Pair(byte[] m, byte[] z) {
  }

  /**
   * Prover-side fold (§2.2.1). Computes {@code Z = k * M} directly from the secret key rather than
   * accumulating it, which is both faster and the reason this variant is called "fast".
   *
   * @param suite the cipher suite
   * @param k     the secret scalar the prover holds
   * @param b     the serialized public key being proven against
   * @param c     the first element list
   * @param d     the second element list
   * @return the folded pair
   */
  static Pair computeCompositesFast(final OprfCipherSuite suite,
                                    final BigInteger k,
                                    final byte[] b,
                                    final byte[][] c,
                                    final byte[][] d) {
    byte[] m = foldFirst(suite, b, c, d);
    // k is the long-term secret; this multiplication stays on the constant-time ladder.
    return new Pair(m, suite.groupSpec().scalarMultiply(k, m));
  }

  /**
   * Verifier-side fold (§2.2.2). Accumulates both composites from the element lists, because the
   * verifier has no key to shortcut {@code Z} with.
   *
   * @param suite the cipher suite
   * @param b     the serialized public key being proven against
   * @param c     the first element list
   * @param d     the second element list
   * @return the folded pair
   */
  static Pair computeComposites(final OprfCipherSuite suite,
                                final byte[] b,
                                final byte[][] c,
                                final byte[][] d) {
    BigInteger[] coefficients = coefficients(suite, b, c, d);
    GroupSpec group = suite.groupSpec();
    // Every d_i is a HashToScalar output over a fully public transcript, so these belong on the
    // fast multiplier rather than the constant-time ladder.
    return new Pair(
        group.linearCombinationPublic(coefficients, c),
        group.linearCombinationPublic(coefficients, d));
  }

  private static byte[] foldFirst(final OprfCipherSuite suite,
                                  final byte[] b,
                                  final byte[][] c,
                                  final byte[][] d) {
    return suite.groupSpec().linearCombinationPublic(coefficients(suite, b, c, d), c);
  }

  /**
   * Derives {@code d_i} for each batch entry.
   * <p>
   * Two details here are easy to get subtly wrong, and wrong in a way that stays self-consistent
   * between a matching prover and verifier while failing every RFC vector. First, {@code seedDST}
   * is transcript <em>data</em>, length-prefixed like any other field — it is not used as a
   * domain-separation tag. Second, {@code seed} is the suite's plain hash of that transcript, not
   * a hash-to-scalar; only {@code d_i} itself is a hash-to-scalar, and it uses the ordinary suite
   * DST {@code "HashToScalar-" || contextString} rather than any proof-specific tag.
   */
  private static BigInteger[] coefficients(final OprfCipherSuite suite,
                                           final byte[] b,
                                           final byte[][] c,
                                           final byte[][] d) {
    validateBatch(c, d);

    byte[] seedDst = ByteUtils.concat(SEED_DST_PREFIX, suite.contextString());
    byte[] seed = suite.hash(ByteUtils.concat(
        ByteUtils.I2OSP(b.length, 2), b,
        ByteUtils.I2OSP(seedDst.length, 2), seedDst));

    BigInteger[] coefficients = new BigInteger[c.length];
    for (int i = 0; i < c.length; i++) {
      byte[] transcript = ByteUtils.concat(
          ByteUtils.I2OSP(seed.length, 2), seed,
          ByteUtils.I2OSP(i, 2),
          ByteUtils.I2OSP(c[i].length, 2), c[i],
          ByteUtils.I2OSP(d[i].length, 2), d[i],
          COMPOSITE_LABEL);
      coefficients[i] = suite.hashToScalar(transcript, suite.hashToScalarDst());
    }
    return coefficients;
  }

  /**
   * RFC 9497 §2.2.1 takes "two non-empty lists"; an empty batch would leave both composites at the
   * identity and degenerate the proof entirely. The upper bound is what the transcript's
   * {@code I2OSP(i, 2)} index can represent.
   */
  static void validateBatch(final byte[][] c, final byte[][] d) {
    if (c == null || d == null) {
      throw new IllegalArgumentException("Batch element lists are required");
    }
    if (c.length != d.length) {
      throw new IllegalArgumentException(
          "Batch element lists must be the same length: " + c.length + " vs " + d.length);
    }
    if (c.length == 0) {
      throw new IllegalArgumentException("Batch must contain at least one element pair");
    }
    if (c.length > MAX_BATCH) {
      throw new IllegalArgumentException(
          "Batch of " + c.length + " exceeds the maximum encodable size of " + MAX_BATCH);
    }
  }
}
