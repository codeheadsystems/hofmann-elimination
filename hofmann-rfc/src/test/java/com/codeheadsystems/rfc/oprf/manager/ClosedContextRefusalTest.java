package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.common.ClosedContextException;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * A closed context is refused by the managers, at the first call rather than a round trip later.
 *
 * <p>This is the test that would have caught the original defect, and the unit tests on the context
 * types would not have: closing zeroed the secret and nothing refused to use the result, so
 * {@code eliminationRequest} and {@code hashResult} kept working and returned well-formed values
 * derived from a run of zeroes.
 *
 * <p><strong>The verifiable modes are the reason this is a test class and not an assertion.</strong>
 * {@code eliminationRequest} there returns the blinded elements the context already holds rather
 * than recomputing them from the input, so a closed VOPRF context used to produce a request the
 * server received correctly, evaluated correctly, and returned a DLEQ proof for that
 * <em>verified</em>. The check that exists to catch a misbehaving server had nothing to say,
 * because the server had not misbehaved. Only the final hash was wrong, and it arrived a full round
 * trip after the mistake was made.
 */
class ClosedContextRefusalTest {

  private static final byte[] SECRET = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INFO = "billing-2026-Q3".getBytes(StandardCharsets.UTF_8);

  private static OprfCipherSuite suite(final OprfMode mode) {
    return OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).withMode(mode).build();
  }

  // ─── base mode ──────────────────────────────────────────────────────────────

  @Test
  void baseMode_eliminationRequestRefusesAClosedContext() {
    OprfCipherSuite suite = suite(OprfMode.OPRF);
    OprfClientManager client = new OprfClientManager(suite);

    ClientHashingContext context = client.hashingContext(SECRET);
    context.close();

    assertThatThrownBy(() -> client.eliminationRequest(context))
        .isInstanceOf(ClosedContextException.class)
        .hasMessageContaining("ClientHashingContext");
  }

  /**
   * The response is obtained honestly first, so the only thing wrong at the point of the assertion
   * is the context's lifetime — not the server, not the wire data.
   */
  @Test
  void baseMode_hashResultRefusesAClosedContext() {
    OprfCipherSuite suite = suite(OprfMode.OPRF);
    OprfClientManager client = new OprfClientManager(suite);
    OprfServerManager server = new OprfServerManager(suite,
        () -> new ServerProcessorDetail(suite.randomScalar(), "key-v1"));

    ClientHashingContext context = client.hashingContext(SECRET);
    EvaluatedResponse response = server.process(client.eliminationRequest(context));
    context.close();

    assertThatThrownBy(() -> client.hashResult(response, context))
        .isInstanceOf(ClosedContextException.class);
  }

  /**
   * The regression assertion, and the one that says the old behaviour was wrong rather than merely
   * unguarded: finalizing over the zeroed input produced a different hash from the real one. It was
   * well-formed, it was the right length, and it was not the answer the caller asked for.
   */
  @Test
  void baseMode_theAnswerAClosedContextUsedToGiveWasNotTheRightOne() {
    OprfCipherSuite suite = suite(OprfMode.OPRF);
    OprfClientManager client = new OprfClientManager(suite);
    OprfServerManager server = new OprfServerManager(suite,
        () -> new ServerProcessorDetail(suite.randomScalar(), "key-v1"));

    ClientHashingContext honest = client.hashingContext(SECRET);
    EvaluatedResponse response = server.process(client.eliminationRequest(honest));
    byte[] correct = client.hashResult(response, honest).hash();

    // Same blind, same evaluated element, but the input zeroed — which is exactly the state a
    // closed context was in, reconstructed here because the guard now makes it unreachable.
    ClientHashingContext zeroed = new ClientHashingContext(
        honest.requestId(), honest.blindingFactor(), new byte[SECRET.length]);
    byte[] fromZeroes = client.hashResult(response, zeroed).hash();

    assertThat(fromZeroes)
        .as("a run of zeroes finalizes to a well-formed hash of the same length")
        .hasSameSizeAs(correct)
        .as("and it is not the hash of the caller's input, which nothing downstream could tell")
        .isNotEqualTo(correct);
  }

  // ─── VOPRF ──────────────────────────────────────────────────────────────────

  /**
   * The heart of the finding. Guarding only {@code inputs()} — the field {@code close()} actually
   * zeroes — would leave this call succeeding, because it never reads the inputs.
   */
  @Test
  void voprf_eliminationRequestRefusesAClosedContext_beforeAnythingReachesTheServer() {
    OprfCipherSuite suite = suite(OprfMode.VOPRF);
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
    VoprfClientManager client = new VoprfClientManager(suite, detail.publicKey());

    VoprfClientContext context = client.hashingContext(List.of(SECRET));
    context.close();

    assertThatThrownBy(() -> client.eliminationRequest(context))
        .as("the request must not be buildable: the server would evaluate it correctly and "
            + "prove it correctly, and only the hash would be wrong")
        .isInstanceOf(ClosedContextException.class)
        .hasMessageContaining("VoprfClientContext");
  }

  /**
   * <strong>The claim the whole finding rests on, asserted rather than described.</strong>
   *
   * <p>Everywhere else — this class's own javadoc, {@code VoprfClientContext.close()}, OPRF.md, the
   * CHANGELOG — the statement "the server evaluates correctly and the DLEQ proof still verifies" is
   * prose. It is also the reason the guard covers {@code blindedElements()} rather than only the
   * field {@code close()} zeroes, so it should be pinned.
   *
   * <p>The closed context is reconstructed the same way the base-mode regression above does it: the
   * request id, blinds and blinded elements exactly as the honest context holds them, because
   * {@code close()} never touches any of the three, paired with zeroed inputs. {@code hashResults}
   * grades the proof against the blinded elements, which are identical — so verification
   * <em>passes</em>, no exception is raised anywhere, and the sole difference is a hash finalized
   * over zeroes. Which is precisely the failure mode: a verifying proof and a wrong answer.
   */
  @Test
  void voprf_theProofUsedToVerifyWhileTheHashWasWrong() {
    OprfCipherSuite suite = suite(OprfMode.VOPRF);
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
    VoprfClientManager client = new VoprfClientManager(suite, detail.publicKey());
    VoprfServerManager server = new VoprfServerManager(suite, () -> detail);

    VoprfClientContext honest = client.hashingContext(List.of(SECRET));
    VerifiableEvaluatedResponse response = server.process(client.eliminationRequest(honest));
    byte[] correct = client.hashResults(response, honest).get(0).hash();

    VoprfClientContext zeroed = new VoprfClientContext(
        honest.requestId(), List.of(new byte[SECRET.length]),
        honest.blinds(), honest.blindedElements());

    byte[] fromZeroes = client.hashResults(response, zeroed).get(0).hash();

    assertThat(fromZeroes)
        .as("the DLEQ check that exists to catch a misbehaving server raised nothing, because the "
            + "server did not misbehave — it evaluated the correct elements correctly")
        .hasSameSizeAs(correct)
        .as("and the only symptom was a hash derived from the wrong input, a round trip late")
        .isNotEqualTo(correct);
  }

  @Test
  void voprf_hashResultsRefusesAClosedContext() {
    OprfCipherSuite suite = suite(OprfMode.VOPRF);
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
    VoprfClientManager client = new VoprfClientManager(suite, detail.publicKey());
    VoprfServerManager server = new VoprfServerManager(suite, () -> detail);

    VoprfClientContext context = client.hashingContext(List.of(SECRET));
    VerifiableEvaluatedResponse response = server.process(client.eliminationRequest(context));
    context.close();

    assertThatThrownBy(() -> client.hashResults(response, context))
        .isInstanceOf(ClosedContextException.class);
  }

  // ─── POPRF ──────────────────────────────────────────────────────────────────

  @Test
  void poprf_eliminationRequestRefusesAClosedContext() {
    OprfCipherSuite suite = suite(OprfMode.POPRF);
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
    PoprfClientManager client = new PoprfClientManager(suite, detail.publicKey());

    PoprfClientContext context = client.hashingContext(List.of(SECRET), INFO);
    context.close();

    assertThatThrownBy(() -> client.eliminationRequest(context))
        .isInstanceOf(ClosedContextException.class)
        .hasMessageContaining("PoprfClientContext");
  }

  /**
   * {@code tweakedKey} is the statement the server's proof is graded against, and it is the one
   * accessor here whose guard has cryptographic content rather than lifetime-hygiene content. It is
   * not zeroed — an all-zero array is the ristretto255 identity encoding, so zeroing it would be
   * actively wrong — but it must not be handed out by an object that has stopped being a context.
   */
  @Test
  void poprf_tweakedKeyIsRefusedAfterClose() {
    OprfCipherSuite suite = suite(OprfMode.POPRF);
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
    PoprfClientManager client = new PoprfClientManager(suite, detail.publicKey());

    PoprfClientContext context = client.hashingContext(List.of(SECRET), INFO);
    context.close();

    assertThatThrownBy(context::tweakedKey).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(context::info).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(context::blinds).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(context::blindedElements).isInstanceOf(ClosedContextException.class);
  }

  // ─── what stays available ───────────────────────────────────────────────────

  /**
   * Correlation metadata survives the close on purpose. A closed context is exactly the thing you
   * want to be able to log about, and refusing everything would make the guard's own failures
   * harder to diagnose than the bug it replaces.
   */
  @Test
  void requestIdSizeToStringAndIsClosedStillAnswer() {
    OprfCipherSuite suite = suite(OprfMode.VOPRF);
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
    VoprfClientManager client = new VoprfClientManager(suite, detail.publicKey());

    VoprfClientContext context = client.hashingContext(List.of(SECRET, SECRET));
    String requestId = context.requestId();
    context.close();

    assertThatCode(() -> {
      assertThat(context.requestId()).isEqualTo(requestId);
      assertThat(context.size()).isEqualTo(2);
      assertThat(context.isClosed()).isTrue();
      assertThat(context.toString()).contains("closed=true");
    }).doesNotThrowAnyException();
  }

  /** Closing twice is fine, and the second close does not change what the guard reports. */
  @Test
  void closeIsIdempotentAcrossAllThreeModes() {
    OprfCipherSuite base = suite(OprfMode.OPRF);
    ClientHashingContext c = new OprfClientManager(base).hashingContext(SECRET);
    c.close();
    c.close();
    assertThat(c.isClosed()).isTrue();

    OprfCipherSuite vsuite = suite(OprfMode.VOPRF);
    VerifiableProcessorDetail vd =
        VerifiableProcessorDetail.derive(vsuite, vsuite.randomScalar(), "key-v1");
    VoprfClientContext v = new VoprfClientManager(vsuite, vd.publicKey())
        .hashingContext(List.of(SECRET));
    v.close();
    v.close();
    assertThat(v.isClosed()).isTrue();

    OprfCipherSuite psuite = suite(OprfMode.POPRF);
    VerifiableProcessorDetail pd =
        VerifiableProcessorDetail.derive(psuite, psuite.randomScalar(), "key-v1");
    PoprfClientContext p = new PoprfClientManager(psuite, pd.publicKey())
        .hashingContext(List.of(SECRET), INFO);
    p.close();
    p.close();
    assertThat(p.isClosed()).isTrue();
  }

  /**
   * {@code ClosedContextException} must not be catchable as the type a hostile server can provoke.
   * The library wraps BouncyCastle's {@code DecoderException} — itself an
   * {@link IllegalStateException} — into {@link SecurityException} so a server cannot pick the
   * exception type an application sees; a lifetime bug filed under that same type would undo it.
   */
  @Test
  void theRefusalIsNotASecurityException() {
    OprfCipherSuite suite = suite(OprfMode.OPRF);
    ClientHashingContext context = new OprfClientManager(suite).hashingContext(SECRET);
    context.close();

    assertThatThrownBy(context::input)
        .isInstanceOf(ClosedContextException.class)
        .isInstanceOf(IllegalStateException.class)
        .isNotInstanceOf(SecurityException.class);
  }
}
