package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Base-mode OPRF against a <em>misbehaving</em> server, driven through the managers.
 *
 * <p>The existing vector tests exercise ristretto255 through {@code groupSpec} directly and only
 * ever with the responses the vectors specify, so no adversarial server response was tested
 * anywhere: every assertion assumed the server had behaved. These go through
 * {@link OprfClientManager}, which is the surface a real client uses, and hand it responses a
 * hostile or broken server could return.
 *
 * <p>Base mode gives a client no cryptographic recourse — that is what VOPRF exists for, and the
 * absence of a proof is the point of the mode rather than a gap in it. So what is asserted here is
 * the honest boundary: which classes of misbehaviour the client <em>detects</em> because they are
 * structurally invalid, and which it cannot detect and silently accepts. Writing the second kind
 * down is as useful as the first, because it is what tells a reader when base mode is not enough.
 */
class OprfAdversarialServerTest {

  private static final BigInteger SERVER_KEY = new BigInteger("4242424242424242424242", 16);
  private static final String INPUT = "correct-horse-battery-staple";

  private OprfCipherSuite suite(CurveHashSuite curveHashSuite) {
    return OprfCipherSuite.builder().withSuite(curveHashSuite).build();
  }

  private EvaluatedResponse evaluateHonestly(OprfCipherSuite suite, BlindedRequest request,
                                             BigInteger key) {
    ServerProcessorDetail detail = new ServerProcessorDetail(key, "test-processor");
    return new OprfServerManager(suite, () -> detail).process(request);
  }

  // ─── detected: structurally invalid responses ───────────────────────────────

  /**
   * The identity is the one that matters. {@code blindInv * O = O}, so accepting it would collapse
   * the OPRF output to a function of the input alone — independent of both the blind and the
   * server key — which is a malicious server silently downgrading the OPRF to an unkeyed hash.
   */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void identityEvaluatedElement_isRejected(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);
    ClientHashingContext context = client.hashingContext(INPUT);

    byte[] identity = curveHashSuite == CurveHashSuite.RISTRETTO255_SHA512
        ? new byte[32] : new byte[]{0x00};
    EvaluatedResponse hostile =
        new EvaluatedResponse(Hex.toHexString(identity), "test-processor");

    assertThatThrownBy(() -> client.hashResult(hostile, context))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void offCurveEvaluatedElement_isRejected(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);
    ClientHashingContext context = client.hashingContext(INPUT);

    byte[] garbage = new byte[suite.groupSpec().elementSize()];
    java.util.Arrays.fill(garbage, (byte) 0xff);
    if (curveHashSuite != CurveHashSuite.RISTRETTO255_SHA512) {
      garbage[0] = 0x02;                       // valid SEC1 prefix, garbage coordinate
    }
    EvaluatedResponse hostile =
        new EvaluatedResponse(Hex.toHexString(garbage), "test-processor");

    assertThatThrownBy(() -> client.hashResult(hostile, context))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void truncatedEvaluatedElement_isRejected(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);
    ClientHashingContext context = client.hashingContext(INPUT);

    EvaluatedResponse hostile = new EvaluatedResponse("0203", "test-processor");

    assertThatThrownBy(() -> client.hashResult(hostile, context))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void nonHexEvaluatedElement_isRejected(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);
    ClientHashingContext context = client.hashingContext(INPUT);

    assertThatThrownBy(() -> client.hashResult(
        new EvaluatedResponse("not-hex-at-all", "test-processor"), context))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class,
            org.bouncycastle.util.encoders.DecoderException.class);
  }

  // ─── not detected, and that is base mode working as specified ───────────────

  /**
   * A server evaluating under the wrong key is <strong>undetectable</strong> in base mode, and
   * this asserts that rather than pretending otherwise.
   *
   * <p>The response is a perfectly well-formed group element; nothing about it is distinguishable
   * from an honest evaluation without a proof. The client unblinds it happily and returns a hash
   * that is simply wrong — stable, plausible, and not the value any other party would compute.
   *
   * <p>This is the gap VOPRF closes, and the reason to reach for mode 0x01 when the server is not
   * trusted to use the key it committed to. A reader who wants this detected wants
   * {@code VoprfClientManager}, where the DLEQ proof fails.
   */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void wrongKeyEvaluation_isAcceptedSilently_whichIsWhyVoprfExists(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);
    ClientHashingContext context = client.hashingContext(INPUT);
    BlindedRequest request = client.eliminationRequest(context);

    HashResult honest = client.hashResult(
        evaluateHonestly(suite, request, SERVER_KEY), context);
    HashResult underWrongKey = client.hashResult(
        evaluateHonestly(suite, request, SERVER_KEY.add(BigInteger.ONE)), context);

    // Both succeed. The client cannot tell them apart — only that they differ, which it has no
    // way to observe with a single response.
    assertThat(honest.hash()).isNotEqualTo(underWrongKey.hash());
  }

  /**
   * A server that swaps in a different client's evaluated element is equally undetectable: the
   * result is well-formed and simply wrong. Recorded for the same reason as above.
   */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void substitutedEvaluationForAnotherInput_isAcceptedSilently(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);

    ClientHashingContext mine = client.hashingContext(INPUT);
    ClientHashingContext theirs = client.hashingContext("someone-elses-input");
    EvaluatedResponse forTheirs =
        evaluateHonestly(suite, client.eliminationRequest(theirs), SERVER_KEY);

    // Unblinding someone else's evaluation with my blind yields a well-formed, wrong hash.
    assertThat(client.hashResult(forTheirs, mine).hash()).isNotEmpty();
  }

  // ─── the honest path still works, per suite ─────────────────────────────────

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void honestRoundTripIsDeterministicPerSuite(CurveHashSuite curveHashSuite) {
    OprfCipherSuite suite = suite(curveHashSuite);
    OprfClientManager client = new OprfClientManager(suite);

    ClientHashingContext first = client.hashingContext(INPUT);
    ClientHashingContext second = client.hashingContext(INPUT);

    byte[] a = client.hashResult(
        evaluateHonestly(suite, client.eliminationRequest(first), SERVER_KEY), first).hash();
    byte[] b = client.hashResult(
        evaluateHonestly(suite, client.eliminationRequest(second), SERVER_KEY), second).hash();

    // Different blinds, same input and key: the whole point of an OPRF.
    assertThat(a).isEqualTo(b);
  }
}
