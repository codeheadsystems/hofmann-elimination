package com.codeheadsystems.rfc.oprf.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.oprf.manager.PoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.PublicInput;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * <strong>Prototype of a non-RFC extension. Nothing here is shipped API.</strong>
 *
 * <p>
 * The question this answers: can a server hold a stored POPRF result, rotate the public input or
 * its secret, recompute the stored value itself, and have a client that later re-runs the protocol
 * under the new parameters arrive at the same value?
 * </p>
 *
 * <h2>Not with the finalized output</h2>
 *
 * <p>
 * {@code finalizeWithInfo} hashes
 * {@code len(input) ‖ input ‖ len(info) ‖ info ‖ len(N) ‖ N ‖ "Finalize"}. Two things stop the
 * server there, and neither is an implementation gap: the output is a hash, so there is nothing to
 * update algebraically, and it binds {@code input}, which the server never learns. A server able to
 * recompute it would be a server able to brute-force the input, which is the property the mode
 * exists to deny.
 * </p>
 *
 * <h2>But the element underneath is updatable</h2>
 *
 * <p>
 * POPRF evaluates {@code N = P · t⁻¹}, where {@code P = HashToGroup(input)} and
 * {@code t = skS + m}. {@code P} does not depend on the key at all, so for any rotation:
 * </p>
 *
 * <pre>
 *   N_new = P · t_new⁻¹ = N_old · (t_old · t_new⁻¹) = N_old · Δ
 * </pre>
 *
 * <p>
 * The server knows {@code skS} and both public inputs, so it can compute {@code Δ} and roll every
 * stored element forward with one scalar multiplication each — without ever seeing an input. The
 * client's finalized output over the rolled element then matches a fresh round trip under the new
 * parameters, which is the property asked for. The cost is that the stored value must be
 * {@code N} rather than the RFC's {@code Finalize} output, which puts the scheme outside RFC 9497's
 * analysis: you lose the input/info binding and the pseudorandomness argument the hash provides.
 * </p>
 *
 * <h2>Why the token cannot be delegated</h2>
 *
 * <p>
 * {@code Δ} is key-equivalent material. The last two tests prove it rather than asserting it: for a
 * public-input rotation {@code Δ} yields {@code skS} outright, and for a secret rotation it is a
 * linear relation between the old and new keys, so compromise of either yields the other. A server
 * may therefore roll its <em>own</em> storage, because {@code Δ} never leaves a process that
 * already holds the secret. Handing {@code Δ} to an untrusted storage tier so it can re-key in
 * place — the usual reason to want update tokens — is not available here.
 * </p>
 *
 * <p>
 * That falls out of RFC 9497 folding the tweak into the key additively ({@code t = skS + m}).
 * Pythia (Everspaugh et al., USENIX Security 2015) is the partially oblivious PRF built for
 * rotation, and it keeps the tweak out of the key via a pairing so that its token is a clean
 * multiplicative factor that reveals nothing.
 * </p>
 */
public class PoprfElementUpdateTest {

  private static final String INPUT = "user@example.com";
  private static final byte[] INFO_Q3 = "billing-2026-Q3".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INFO_Q4 = "billing-2026-Q4".getBytes(StandardCharsets.UTF_8);

  /**
   * All suites stream.
   *
   * @return the stream
   */
  static Stream<OprfCipherSuite> allSuites() {
    return Stream.of(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build(),
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P384_SHA384).withMode(OprfMode.POPRF).build(),
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P521_SHA512).withMode(OprfMode.POPRF).build(),
        OprfCipherSuite.builder().withSuite(CurveHashSuite.RISTRETTO255_SHA512).withMode(OprfMode.POPRF).build()
    );
  }

  private static VerifiableProcessorDetail detail(final OprfCipherSuite suite) {
    return VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "SP:" + UUID.randomUUID());
  }

  // ─── The primitives a real implementation would expose ──────────────────────

  /**
   * Runs one honest exchange and returns {@code N}, the unblinded element the finalized hash is
   * built from.
   *
   * <p>
   * {@code OprfCipherSuite.unblind} is package-private, so the unblinding is written out here:
   * {@code N = blind⁻¹ · R}, exactly what it does. The proof is still verified — {@code hashResult}
   * is called and its output discarded — so this is not a path that skips the mode's guarantee.
   * </p>
   */
  private static byte[] evaluateElement(final OprfCipherSuite suite,
                                        final PoprfClientManager client,
                                        final PoprfServerManager server,
                                        final byte[] info) {
    try (PoprfClientContext context = client.hashingContext(INPUT, info)) {
      PartiallyEvaluatedResponse response = server.process(client.eliminationRequest(context));
      client.hashResult(response, context);
      BigInteger blind = context.blinds().get(0);
      byte[] evaluated = Hex.decode(response.evaluatedPoints().get(0));
      return suite.groupSpec().scalarMultiply(suite.scalarInverse(blind), evaluated);
    }
  }

  /** The effective key an evaluation runs under: {@code t = skS + m mod n}. */
  private static BigInteger tweakedKey(final OprfCipherSuite suite,
                                       final BigInteger secret,
                                       final byte[] info) {
    return secret.add(PublicInput.toScalar(suite, info)).mod(suite.groupSpec().groupOrder());
  }

  /** The update token: {@code Δ = t_old · t_new⁻¹ mod n}. Server-side only — see the class doc. */
  private static BigInteger updateToken(final OprfCipherSuite suite,
                                        final BigInteger tweakedOld,
                                        final BigInteger tweakedNew) {
    return tweakedOld.multiply(suite.scalarInverse(tweakedNew)).mod(suite.groupSpec().groupOrder());
  }

  /** Rolls a stored element forward. One scalar multiplication, no knowledge of the input. */
  private static byte[] applyToken(final OprfCipherSuite suite,
                                   final BigInteger token,
                                   final byte[] storedElement) {
    return suite.groupSpec().scalarMultiply(token, storedElement);
  }

  /**
   * The finalized output over an element the caller already holds.
   *
   * <p>
   * {@code finalizeWithInfo} expects the pre-unblind element and a blind; passing a blind of one
   * makes the unblinding a no-op, so this finalizes {@code N} directly. Only the client can do
   * this — it needs {@code input}.
   * </p>
   */
  private static byte[] finalizeOver(final OprfCipherSuite suite,
                                     final byte[] info,
                                     final byte[] element) {
    return suite.finalizeWithInfo(
        INPUT.getBytes(StandardCharsets.UTF_8), info, BigInteger.ONE, element);
  }

  // ─── Rolling stored elements forward ────────────────────────────────────────

  /**
   * The headline: the server rolls a stored element from one public input to the next, and a client
   * running a fresh exchange under the new public input lands on the same element — and therefore
   * on the same finalized output.
   *
   * <p>
   * The second assertion is the one that answers the question. The server maintained the stored
   * value without learning the input; the client, which does know the input, finalizes over the
   * server's rolled element and gets exactly what an honest round trip under the new public input
   * produces.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "rollInfo_{0}")
  @MethodSource("allSuites")
  void serverRollsStoredElementsToANewPublicInput(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> key);
    PoprfClientManager client = new PoprfClientManager(suite, key.publicKey());

    byte[] storedQ3 = evaluateElement(suite, client, server, INFO_Q3);

    // Server side only: nothing below touches the input, and no client is involved.
    BigInteger token = updateToken(suite,
        tweakedKey(suite, key.masterKey(), INFO_Q3),
        tweakedKey(suite, key.masterKey(), INFO_Q4));
    byte[] rolled = applyToken(suite, token, storedQ3);

    byte[] freshQ4 = evaluateElement(suite, client, server, INFO_Q4);

    assertThat(storedQ3)
        .as("the token has real work to do — the periods evaluate to different elements")
        .isNotEqualTo(freshQ4);
    assertThat(rolled).as("rolled element matches a fresh evaluation").isEqualTo(freshQ4);
    assertThat(finalizeOver(suite, INFO_Q4, rolled))
        .as("and so the client's finalized output matches")
        .isEqualTo(finalizeOver(suite, INFO_Q4, freshQ4));
  }

  /**
   * The same roll, but across a rotated secret with the public input held fixed. The client has to
   * be reissued with the new public key before it can verify, which is the operational cost
   * rotation carries and the tweak does not.
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "rollSecret_{0}")
  @MethodSource("allSuites")
  void serverRollsStoredElementsToARotatedSecret(OprfCipherSuite suite) {
    VerifiableProcessorDetail oldKey = detail(suite);
    VerifiableProcessorDetail newKey = detail(suite);

    byte[] stored = evaluateElement(suite,
        new PoprfClientManager(suite, oldKey.publicKey()),
        new PoprfServerManager(suite, () -> oldKey),
        INFO_Q3);

    BigInteger token = updateToken(suite,
        tweakedKey(suite, oldKey.masterKey(), INFO_Q3),
        tweakedKey(suite, newKey.masterKey(), INFO_Q3));
    byte[] rolled = applyToken(suite, token, stored);

    byte[] fresh = evaluateElement(suite,
        new PoprfClientManager(suite, newKey.publicKey()),
        new PoprfServerManager(suite, () -> newKey),
        INFO_Q3);

    assertThat(stored).as("the two secrets evaluate to different elements").isNotEqualTo(fresh);
    assertThat(rolled).isEqualTo(fresh);
    assertThat(finalizeOver(suite, INFO_Q3, rolled)).isEqualTo(finalizeOver(suite, INFO_Q3, fresh));
  }

  /**
   * Both at once. {@code Δ} is a single scalar regardless of how many parameters moved, so rotating
   * the secret and advancing the period is one pass over storage, not two.
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "rollBoth_{0}")
  @MethodSource("allSuites")
  void serverRollsStoredElementsAcrossBothAtOnce(OprfCipherSuite suite) {
    VerifiableProcessorDetail oldKey = detail(suite);
    VerifiableProcessorDetail newKey = detail(suite);

    byte[] stored = evaluateElement(suite,
        new PoprfClientManager(suite, oldKey.publicKey()),
        new PoprfServerManager(suite, () -> oldKey),
        INFO_Q3);

    BigInteger token = updateToken(suite,
        tweakedKey(suite, oldKey.masterKey(), INFO_Q3),
        tweakedKey(suite, newKey.masterKey(), INFO_Q4));
    byte[] rolled = applyToken(suite, token, stored);

    byte[] fresh = evaluateElement(suite,
        new PoprfClientManager(suite, newKey.publicKey()),
        new PoprfServerManager(suite, () -> newKey),
        INFO_Q4);

    assertThat(stored).as("both parameters moved, so the elements differ").isNotEqualTo(fresh);
    assertThat(rolled).isEqualTo(fresh);
    assertThat(finalizeOver(suite, INFO_Q4, rolled)).isEqualTo(finalizeOver(suite, INFO_Q4, fresh));
  }

  // ─── Why the token cannot leave the server ──────────────────────────────────

  /**
   * The token for a public-input rotation reveals the secret key outright.
   *
   * <p>
   * With the secret unchanged, {@code Δ = (skS + m₀) / (skS + m₁)}, and both {@code m} values are
   * derived from public inputs by a public function. One equation, one unknown:
   * </p>
   *
   * <pre>
   *   skS = (m₀ − Δ·m₁) / (Δ − 1)
   * </pre>
   *
   * <p>
   * This test performs that recovery and checks it against the real key. It is the reason the
   * class doc says a server may roll its own storage but may not hand {@code Δ} to anyone.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "tokenLeaksKey_{0}")
  @MethodSource("allSuites")
  void theTokenForAPublicInputRotationRevealsTheSecretKey(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    BigInteger n = suite.groupSpec().groupOrder();

    BigInteger token = updateToken(suite,
        tweakedKey(suite, key.masterKey(), INFO_Q3),
        tweakedKey(suite, key.masterKey(), INFO_Q4));

    // Everything below is computable by whoever holds the token. No secret is used.
    BigInteger m0 = PublicInput.toScalar(suite, INFO_Q3);
    BigInteger m1 = PublicInput.toScalar(suite, INFO_Q4);
    BigInteger recovered = m0.subtract(token.multiply(m1)).mod(n)
        .multiply(suite.scalarInverse(token.subtract(BigInteger.ONE).mod(n)))
        .mod(n);

    assertThat(recovered)
        .as("the update token alone yields the server secret")
        .isEqualTo(key.masterKey());
  }

  /**
   * The token for a secret rotation does not reveal either key on its own — two unknowns, one
   * equation — but it ties them together as {@code skS_old = Δ·skS_new + m·(Δ − 1)}. Anyone holding
   * the token and either key derives the other, so a token that outlives a compromise hands over
   * the key that replaced it.
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "tokenLinksKeys_{0}")
  @MethodSource("allSuites")
  void theTokenForASecretRotationLinksTheOldAndNewKeys(OprfCipherSuite suite) {
    VerifiableProcessorDetail oldKey = detail(suite);
    VerifiableProcessorDetail newKey = detail(suite);
    BigInteger n = suite.groupSpec().groupOrder();

    BigInteger token = updateToken(suite,
        tweakedKey(suite, oldKey.masterKey(), INFO_Q3),
        tweakedKey(suite, newKey.masterKey(), INFO_Q3));

    BigInteger m = PublicInput.toScalar(suite, INFO_Q3);
    BigInteger reconstructed = token.multiply(newKey.masterKey())
        .add(m.multiply(token.subtract(BigInteger.ONE)))
        .mod(n);

    assertThat(reconstructed)
        .as("token plus the new key yields the old one")
        .isEqualTo(oldKey.masterKey());
  }

  // ─── The boundary of the technique ──────────────────────────────────────────

  /**
   * A reminder of what is <em>not</em> being claimed. The stored element is updatable; the finalized
   * output is not, and the two evaluations differ in a way no scalar can bridge, because the hash
   * destroys the group structure the token acts on.
   *
   * <p>
   * A scheme built on this must therefore store {@code N} and finalize at comparison time. Storing
   * the RFC output and hoping to migrate it later is the one shape that does not work.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "hashIsNotUpdatable_{0}")
  @MethodSource("allSuites")
  void theFinalizedOutputIsNotWhatGetsRolled(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> key);
    PoprfClientManager client = new PoprfClientManager(suite, key.publicKey());

    HashResult q3;
    HashResult q4;
    try (PoprfClientContext c3 = client.hashingContext(INPUT, INFO_Q3)) {
      q3 = client.hashResult(server.process(client.eliminationRequest(c3)), c3);
    }
    try (PoprfClientContext c4 = client.hashingContext(INPUT, INFO_Q4)) {
      q4 = client.hashResult(server.process(client.eliminationRequest(c4)), c4);
    }

    assertThat(q3.hash()).isNotEqualTo(q4.hash());

    // The element that produced each hash is what the token relates; the hashes themselves are
    // opaque, and the server holds neither the input nor a way to recompute them.
    byte[] storedQ3 = evaluateElement(suite, client, server, INFO_Q3);
    BigInteger token = updateToken(suite,
        tweakedKey(suite, key.masterKey(), INFO_Q3),
        tweakedKey(suite, key.masterKey(), INFO_Q4));

    assertThat(finalizeOver(suite, INFO_Q4, applyToken(suite, token, storedQ3)))
        .as("finalizing over the rolled element reproduces the real Q4 output")
        .isEqualTo(q4.hash());
  }
}
