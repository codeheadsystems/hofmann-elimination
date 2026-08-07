package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.PartiallyBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.PublicInput;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProof;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProver;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Behavioural and negative coverage for the POPRF managers. Conformance against fixed RFC bytes
 * lives in {@link PoprfVectorsTest}.
 */
class PoprfManagerTest {

  private static final byte[] INFO = "test info".getBytes(StandardCharsets.UTF_8);

  static Stream<Arguments> suites() {
    return Stream.of(CurveHashSuite.values())
        .map(c -> Arguments.of(c.name(),
            OprfCipherSuite.builder().withSuite(c).withMode(OprfMode.POPRF).build()));
  }

  private static VerifiableProcessorDetail detail(OprfCipherSuite suite) {
    return VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
  }

  // ─── happy path ─────────────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void roundTripSucceeds(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext context = client.hashingContext("hunter2", INFO);
    HashResult result = client.hashResult(server.process(client.eliminationRequest(context)), context);

    assertThat(result.hash()).hasSize(suite.hashOutputLength());
    assertThat(result.processIdentifier()).isEqualTo("key-v1");
  }

  /** The public input separates evaluations: same input, different info, different output. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void differentPublicInputsGiveDifferentOutputs(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext first = client.hashingContext("same", "info-a".getBytes(StandardCharsets.UTF_8));
    PoprfClientContext second = client.hashingContext("same", "info-b".getBytes(StandardCharsets.UTF_8));

    assertThat(client.hashResult(server.process(client.eliminationRequest(first)), first).hash())
        .isNotEqualTo(
            client.hashResult(server.process(client.eliminationRequest(second)), second).hash());
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void emptyPublicInputIsUsable(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext context = client.hashingContext("x", new byte[0]);
    assertThatCode(() ->
        client.hashResult(server.process(client.eliminationRequest(context)), context))
        .doesNotThrowAnyException();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void batchRoundTripMatchesIndividualEvaluations(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    List<byte[]> inputs = List.of(
        "alpha".getBytes(StandardCharsets.UTF_8),
        "beta".getBytes(StandardCharsets.UTF_8));

    PoprfClientContext batch = client.hashingContext(inputs, INFO);
    List<HashResult> batched =
        client.hashResults(server.process(client.eliminationRequest(batch)), batch);

    for (int i = 0; i < inputs.size(); i++) {
      PoprfClientContext single = client.hashingContext(List.of(inputs.get(i)), INFO);
      assertThat(batched.get(i).hash()).as("input %d", i).isEqualTo(
          client.hashResult(server.process(client.eliminationRequest(single)), single).hash());
    }
  }

  // ─── public input binding ───────────────────────────────────────────────────

  /**
   * The heart of the mode: a server that evaluates under a different public input than the client
   * asked for must be caught, not silently produce a different output. The client grades the proof
   * against a tweaked key it derived from its own {@code info}, so the substitution changes the
   * key the proof must satisfy.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAnEvaluationUnderADifferentPublicInput(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext context = client.hashingContext("secret", INFO);
    PartiallyBlindedRequest honest = client.eliminationRequest(context);

    // The server answers the same blinded elements under a different public input.
    PartiallyBlindedRequest substituted = new PartiallyBlindedRequest(
        honest.blindedPoints(),
        Hex.toHexString("other info".getBytes(StandardCharsets.UTF_8)),
        honest.requestId());
    PartiallyEvaluatedResponse response = server.process(substituted);

    assertThatThrownBy(() -> client.hashResult(response, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAnEvaluationUnderADifferentKey(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail honest = detail(suite);
    VerifiableProcessorDetail rogue =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "rogue");

    PoprfServerManager rogueServer = new PoprfServerManager(suite, () -> rogue);
    PoprfClientManager client = new PoprfClientManager(suite, honest.publicKey());

    PoprfClientContext context = client.hashingContext("secret", INFO);
    PartiallyEvaluatedResponse response = rogueServer.process(client.eliminationRequest(context));

    assertThatThrownBy(() -> client.hashResult(response, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  /**
   * A proof built with the element lists in VOPRF order — {@code (blinded, evaluated)} rather than
   * POPRF's {@code (evaluated, blinded)} — must not verify, even though it is generated with the
   * correct tweaked key over the correct elements.
   * <p>
   * This is the guard that makes the reversal real rather than a convention the implementation
   * shares with itself. A prover and verifier that both had the order backwards would interoperate
   * perfectly; only a proof built the other way round can distinguish them. Everything else here
   * is honest — same {@code t}, same {@code B}, same elements — so the only reason it fails is the
   * ordering.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAProofOverTheListsInVoprfOrder(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext context = client.hashingContext(List.of(
        "one".getBytes(StandardCharsets.UTF_8),
        "two".getBytes(StandardCharsets.UTF_8)), INFO);
    PartiallyEvaluatedResponse honest = server.process(client.eliminationRequest(context));

    // Reconstruct exactly what the server proved with.
    BigInteger t = d.masterKey().add(PublicInput.toScalar(suite, INFO))
        .mod(suite.groupSpec().groupOrder());
    byte[] tweakedPublicKey = suite.groupSpec().scalarMultiplyGenerator(t);
    byte[][] evaluated = honest.evaluatedPoints().stream().map(Hex::decode).toArray(byte[][]::new);
    byte[][] blinded = context.blindedElements().toArray(new byte[0][]);

    // The honest proof verifies; the same proof over the lists swapped does not.
    assertThatCode(() -> client.hashResults(honest, context)).doesNotThrowAnyException();

    DleqProof voprfOrdered = DleqProver.generateProof(
        suite, t, tweakedPublicKey, blinded, evaluated);
    PartiallyEvaluatedResponse wrongOrder = new PartiallyEvaluatedResponse(
        honest.evaluatedPoints(),
        Hex.toHexString(voprfOrdered.serialize(suite)),
        honest.processIdentifier());

    assertThatThrownBy(() -> client.hashResults(wrongOrder, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  /** A permuted batch must also be rejected — the case a length check alone would miss. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAPermutedResponse(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext context = client.hashingContext(List.of(
        "one".getBytes(StandardCharsets.UTF_8),
        "two".getBytes(StandardCharsets.UTF_8)), INFO);
    PartiallyEvaluatedResponse honest = server.process(client.eliminationRequest(context));

    PartiallyEvaluatedResponse permuted = new PartiallyEvaluatedResponse(
        List.of(honest.evaluatedPoints().get(1), honest.evaluatedPoints().get(0)),
        honest.proof(), honest.processIdentifier());

    assertThatThrownBy(() -> client.hashResults(permuted, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAResponseOfTheWrongLength(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext context = client.hashingContext(List.of(
        "one".getBytes(StandardCharsets.UTF_8),
        "two".getBytes(StandardCharsets.UTF_8)), INFO);
    PartiallyEvaluatedResponse full = server.process(client.eliminationRequest(context));

    assertThatThrownBy(() -> client.hashResults(new PartiallyEvaluatedResponse(
        List.of(full.evaluatedPoints().get(0)), full.proof(), full.processIdentifier()), context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("evaluated elements");
  }

  // ─── the degenerate public input ────────────────────────────────────────────

  /**
   * RFC 9497 §3.3.3 raises {@code InverseError} when {@code t = skS + m} is zero, and is explicit
   * that a client causing it should be assumed to know the server's private key. Constructed here
   * by choosing the secret key to be the negation of a known public input's scalar — which is
   * exactly the knowledge the RFC says such a client must have.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void serverRefusesAPublicInputThatZeroesTheTweakedKey(String name, OprfCipherSuite suite) {
    BigInteger n = suite.groupSpec().groupOrder();
    BigInteger m = PublicInput.toScalar(suite, INFO);
    BigInteger skS = n.subtract(m).mod(n);

    VerifiableProcessorDetail d = VerifiableProcessorDetail.derive(suite, skS, "doomed");
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);

    // A blinded element is still needed; any valid element will do since the failure precedes use.
    byte[] element = suite.groupSpec().scalarMultiplyGenerator(suite.randomScalar());
    PartiallyBlindedRequest request = new PartiallyBlindedRequest(
        List.of(Hex.toHexString(element)), Hex.toHexString(INFO), "req");

    assertThatThrownBy(() -> server.process(request))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("compromised");
  }

  /**
   * The client-side counterpart: with that same key, {@code m*G + pkS} is the identity, which
   * §3.3.3 {@code Blind} requires the client to detect.
   * <p>
   * Note what this does and does not establish. It shows the condition is detected and reported as
   * the identity case. It does <em>not</em> discriminate between building the tweaked key as a
   * multi-scalar operation and composing {@code add(scalarMultiplyGenerator(m), pkS)} — with
   * {@code m != 0}, as here, the composed form would reach the same identity as its sum and raise
   * the same exception. The two only diverge at {@code m == 0}, where
   * {@code scalarMultiplyGenerator(0)} yields a one-byte identity encoding that {@code add}'s
   * deserializer would reject as a malformed input instead.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRefusesAPublicInputThatZeroesTheTweakedKey(String name, OprfCipherSuite suite) {
    BigInteger n = suite.groupSpec().groupOrder();
    BigInteger m = PublicInput.toScalar(suite, INFO);
    BigInteger skS = n.subtract(m).mod(n);
    byte[] pkS = suite.derivePublicKey(skS);

    PoprfClientManager client = new PoprfClientManager(suite, pkS);

    assertThatThrownBy(() -> client.hashingContext("x", INFO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("identity element");
  }

  // ─── public input bounds ────────────────────────────────────────────────────

  @Test
  void publicInputLengthIsBounded() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    assertThatCode(() -> client.hashingContext("x", new byte[PublicInput.MAX_LENGTH]))
        .doesNotThrowAnyException();
    assertThatThrownBy(() -> client.hashingContext("x", new byte[PublicInput.MAX_LENGTH + 1]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exceeds the maximum");
    assertThatThrownBy(() -> client.hashingContext("x", null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  // ─── server-side validation ─────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void serverRejectsTheIdentityElement(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);

    assertThatThrownBy(() -> server.process(new PartiallyBlindedRequest(
        List.of(Hex.toHexString(new byte[suite.elementSize()])), Hex.toHexString(INFO), "req")))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  @Test
  void serverRejectsMalformedHexAsAClientError() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d);

    assertThatThrownBy(() -> server.process(
        new PartiallyBlindedRequest(List.of("nothex"), Hex.toHexString(INFO), "r")))
        .isInstanceOf(IllegalArgumentException.class)
        .isNotInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> server.process(
        new PartiallyBlindedRequest(List.of("00"), "nothex", "r")))
        .isInstanceOf(IllegalArgumentException.class)
        .isNotInstanceOf(IllegalStateException.class);
  }

  @Test
  void serverEnforcesTheBatchCap() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> d, 2);
    PoprfClientManager client = new PoprfClientManager(suite, d.publicKey());

    PoprfClientContext tooBig = client.hashingContext(List.of(
        "a".getBytes(StandardCharsets.UTF_8),
        "b".getBytes(StandardCharsets.UTF_8),
        "c".getBytes(StandardCharsets.UTF_8)), INFO);

    assertThatThrownBy(() -> server.process(client.eliminationRequest(tooBig)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exceeds the configured maximum");
  }

  @Test
  void serverRejectsKeyMaterialFromAnotherMode() {
    OprfCipherSuite partial = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    OprfCipherSuite verifiable = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();

    VerifiableProcessorDetail voprfKey =
        VerifiableProcessorDetail.derive(verifiable, verifiable.randomScalar(), "voprf-key");
    PoprfServerManager server = new PoprfServerManager(partial, () -> voprfKey);
    PoprfClientManager client = new PoprfClientManager(partial, voprfKey.publicKey());

    assertThatThrownBy(() ->
        server.process(client.eliminationRequest(client.hashingContext("x", INFO))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("wrong mode");
  }

  // ─── mode enforcement ───────────────────────────────────────────────────────

  @Test
  void managersRejectANonPoprfSuite() {
    OprfCipherSuite base = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).build();
    OprfCipherSuite verifiable = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    OprfCipherSuite partial = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    VerifiableProcessorDetail d = detail(partial);

    for (OprfCipherSuite wrong : List.of(base, verifiable)) {
      assertThatThrownBy(() -> new PoprfServerManager(wrong, () -> d))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> new PoprfClientManager(wrong, d.publicKey()))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Test
  void contextRejectsMissingPoprfState() {
    assertThatThrownBy(() -> new PoprfClientContext("id", List.of(new byte[]{1}),
        List.of(BigInteger.ONE), List.of(new byte[]{2}), null, new byte[]{3}))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Public input is required");
    assertThatThrownBy(() -> new PoprfClientContext("id", List.of(new byte[]{1}),
        List.of(BigInteger.ONE), List.of(new byte[]{2}), new byte[0], null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Tweaked key is required");
  }
}
