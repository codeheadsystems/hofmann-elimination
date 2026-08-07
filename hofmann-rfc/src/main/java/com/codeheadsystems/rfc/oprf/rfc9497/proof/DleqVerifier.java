package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.IdentityResultException;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RFC 9497 §2.2.2 {@code VerifyProof}.
 */
public final class DleqVerifier {

  private static final Logger log = LoggerFactory.getLogger(DleqVerifier.class);

  private DleqVerifier() {
  }

  /**
   * Verifies a proof over a batch.
   * <p>
   * Returns a boolean rather than throwing, and does so for <em>every</em> failure mode. A proof
   * that fails because an element computed to the identity, or because a supplied element was not
   * a valid encoding, must be indistinguishable to the caller from one that simply did not verify:
   * an exception escaping here would let a remote party tell those cases apart, and would push
   * callers into rendering a bad proof as a server error rather than a rejected response.
   * <p>
   * The identity cases are worth being concrete about, because refusing them is a deliberate
   * choice rather than a limitation. {@code t2 = s*G + c*B} is the identity exactly when
   * {@code s = -c*k}, which only a party holding {@code k} can arrange — and a prover that did so
   * would be publishing its own key, since {@code k = -s/c}. An honest prover reaches the same
   * state only by drawing {@code r = 0}, which {@link OprfCipherSuite#randomScalar()} never
   * produces. So the rejected set is "proofs no honest prover generates", and treating them as
   * invalid costs nothing.
   *
   * @param suite the cipher suite, whose mode fixes the domain separation
   * @param b     the serialized public key the proof is graded against
   * @param c     the first element list
   * @param d     the second element list
   * @param proof the proof to check
   * @return whether the proof verifies
   */
  public static boolean verifyProof(final OprfCipherSuite suite,
                                    final byte[] b,
                                    final byte[][] c,
                                    final byte[][] d,
                                    final DleqProof proof) {
    suite.assertMode(OprfMode.VOPRF, OprfMode.POPRF);
    if (proof == null) {
      return false;
    }
    // Deliberately outside the try. A null, empty, or length-mismatched batch is a caller bug —
    // most likely a manager that failed to check the server returned as many evaluated elements as
    // it was sent — and swallowing it as "the proof did not verify" would hide exactly the defect
    // that mismatch represents. Everything below this point is attacker-influenced and must fail
    // uniformly.
    Composites.validateBatch(c, d);
    try {
      GroupSpec group = suite.groupSpec();
      Composites.Pair composites = Composites.computeComposites(suite, b, c, d);

      // Both scalars arrive from the wire and are public, so these use the fast multiplier.
      // Neither term may be computed separately: a remote party can set s = 0, which makes
      // s*G the identity, and the identity has no Ne-byte encoding to hand to add().
      BigInteger[] scalars = {proof.s(), proof.c()};
      byte[] t2 = group.linearCombinationPublic(scalars, new byte[][]{group.generator(), b});
      byte[] t3 = group.linearCombinationPublic(scalars, new byte[][]{composites.m(), composites.z()});

      BigInteger expected = Challenge.compute(suite, b, composites, t2, t3);

      // Compared as fixed-width encodings under a constant-time comparison, rather than with
      // BigInteger.equals, which short-circuits on the first differing limb.
      //
      // Stated honestly: no known attack needs this. The expected challenge is a function *of* the
      // submitted c — through t2 = s*G + c*B and t3 = s*M + c*Z — so each trial c yields a fresh,
      // unrelated expected value, and a partial-match oracle gives an attacker no way to extend a
      // match incrementally. This is defence-in-depth against a comparison whose cost is zero, not
      // a fix for a demonstrated break.
      return MessageDigest.isEqual(
          group.serializeScalar(expected),
          group.serializeScalar(proof.c()));
    } catch (IdentityResultException e) {
      log.debug("Proof verification failed: a proof element computed to the identity: {}",
          e.getMessage());
      return false;
    } catch (SecurityException | IllegalArgumentException e) {
      log.debug("Proof verification failed on malformed input: {}", e.getMessage());
      return false;
    }
  }
}
