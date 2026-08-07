package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;

/**
 * RFC 9497 §2.2.1 {@code GenerateProof}.
 * <p>
 * Proves, without revealing {@code k}, that the same {@code k} relates {@code B} to the generator
 * as relates each {@code D[i]} to the corresponding {@code C[i]}. The verifiable OPRF modes use
 * this to let a client confirm the server evaluated with its committed key.
 *
 * <p><strong>The proof randomness must be fresh for every proof.</strong> Two proofs under one key
 * that reuse {@code r} expose it directly: {@code c1} and {@code c2} differ, both {@code s} values
 * are published, and {@code k = (s1 - s2) / (c2 - c1)}. This is the same break that ECDSA nonce
 * reuse gives, and it recovers the server's long-term key from two observed responses. It must
 * also not be biased, derived from anything the client influences, or derived deterministically
 * from {@code (k, message)} unless via a proper HMAC-DRBG in the manner of RFC 6979 — partial bias
 * in {@code r} is recoverable by lattice methods exactly as it is for ECDSA nonces.
 * {@link OprfCipherSuite#randomScalar()} is an unbiased rejection sampler over {@code [1, n-1]},
 * which is what makes the public entry point here safe.
 *
 * <p><strong>Residual, stated rather than glossed:</strong> the group operations here run on the
 * constant-time ladder, but {@code s = r - c*k} does not — {@link java.math.BigInteger}
 * multiplication and reduction are variable-time in their operands, and RFC 9497 §7.4 names
 * {@code GenerateProof} as an operation that should be constant time. The exposure is far smaller
 * than the scalar-multiplication leaks this module already closes: the operands are fixed-width
 * after the first reduction, and {@code s} is published in the proof regardless. Removing it
 * entirely would need constant-time scalar-field arithmetic that {@code BigInteger} does not
 * offer.
 */
public final class DleqProver {

  private DleqProver() {
  }

  /**
   * Generates a proof over a batch, sampling the proof randomness from the suite.
   *
   * @param suite the cipher suite, whose mode fixes the domain separation
   * @param k     the secret scalar
   * @param b     the serialized public key {@code B = k * G}
   * @param c     the first element list
   * @param d     the second element list, where {@code d[i] = k * c[i]}
   * @return the proof
   */
  public static DleqProof generateProof(final OprfCipherSuite suite,
                                        final BigInteger k,
                                        final byte[] b,
                                        final byte[][] c,
                                        final byte[][] d) {
    return generateProof(suite, k, b, c, d, suite.randomScalar());
  }

  /**
   * Generates a proof with caller-supplied randomness.
   * <p>
   * Package-private, and deliberately so: this exists only to reproduce the fixed
   * {@code ProofRandomScalar} values in the RFC 9497 Appendix A vectors, which cannot be reached
   * through the suite's rejection sampler. Nothing outside this package may call it, because a
   * caller that supplies {@code r} owns the one input whose reuse or bias hands over the server's
   * long-term key.
   *
   * @param r the proof randomness, which must lie in {@code [1, n-1]}
   */
  static DleqProof generateProof(final OprfCipherSuite suite,
                                 final BigInteger k,
                                 final byte[] b,
                                 final byte[][] c,
                                 final byte[][] d,
                                 final BigInteger r) {
    suite.assertMode(OprfMode.VOPRF, OprfMode.POPRF);
    BigInteger n = suite.groupSpec().groupOrder();
    if (r == null || r.signum() <= 0 || r.compareTo(n) >= 0) {
      throw new IllegalArgumentException("Proof randomness must be a scalar in [1, n-1]");
    }
    // Batch shape is validated inside computeCompositesFast, on the path every caller takes.

    Composites.Pair composites = Composites.computeCompositesFast(suite, k, b, c, d);

    // r is secret: both of these stay on the constant-time ladder.
    byte[] t2 = suite.groupSpec().scalarMultiplyGenerator(r);
    byte[] t3 = suite.groupSpec().scalarMultiply(r, composites.m());

    BigInteger challenge = Challenge.compute(suite, b, composites, t2, t3);

    // Reducing mod n is not optional. BigInteger.subtract yields a negative for the common case
    // c*k > r, which serializeScalar rejects outright on the Weierstrass curves.
    BigInteger s = r.subtract(challenge.multiply(k)).mod(n);

    return new DleqProof(challenge, s);
  }
}
