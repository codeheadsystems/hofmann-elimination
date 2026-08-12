package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.IdentityEncodings;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.VerifiableBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Behavioural and negative coverage for the VOPRF managers. Conformance against fixed RFC bytes
 * lives in {@link VoprfVectorsTest}.
 */
class VoprfManagerTest {

  static Stream<Arguments> suites() {
    return Stream.of(CurveHashSuite.values())
        .map(c -> Arguments.of(c.name(),
            OprfCipherSuite.builder().withSuite(c).withMode(OprfMode.VOPRF).build()));
  }

  private static VerifiableProcessorDetail detail(OprfCipherSuite suite) {
    return VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "key-v1");
  }

  // ─── happy path ─────────────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void roundTripSucceeds(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext context = client.hashingContext("hunter2");
    HashResult result = client.hashResult(server.process(client.eliminationRequest(context)), context);

    assertThat(result.hash()).hasSize(suite.hashOutputLength());
    assertThat(result.processIdentifier()).isEqualTo("key-v1");
  }

  /** The same input under the same key must give the same output, whatever the blind. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void outputIsIndependentOfTheBlind(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext first = client.hashingContext("same-input");
    VoprfClientContext second = client.hashingContext("same-input");
    assertThat(first.blinds()).isNotEqualTo(second.blinds());

    assertThat(client.hashResult(server.process(client.eliminationRequest(first)), first).hash())
        .isEqualTo(
            client.hashResult(server.process(client.eliminationRequest(second)), second).hash());
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void batchRoundTripMatchesIndividualEvaluations(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    List<byte[]> inputs = List.of(
        "alpha".getBytes(StandardCharsets.UTF_8),
        "beta".getBytes(StandardCharsets.UTF_8),
        "gamma".getBytes(StandardCharsets.UTF_8));

    VoprfClientContext batch = client.hashingContext(inputs);
    List<HashResult> batched = client.hashResults(server.process(client.eliminationRequest(batch)), batch);

    assertThat(batched).hasSize(3);
    for (int i = 0; i < inputs.size(); i++) {
      VoprfClientContext single = client.hashingContext(List.of(inputs.get(i)));
      HashResult alone = client.hashResult(server.process(client.eliminationRequest(single)), single);
      assertThat(batched.get(i).hash()).as("input %d", i).isEqualTo(alone.hash());
    }
  }

  // ─── public key handling ────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAnUnusablePublicKey(String name, OprfCipherSuite suite) {
    // The identity, which is a structurally valid encoding refused on its value. Previously this
    // case was new byte[elementSize()], which on the SEC1 suites is merely malformed — so the
    // identity public key, the one that makes every proof verify against a zero key, was only
    // ever tested on ristretto255.
    assertThatThrownBy(() -> new VoprfClientManager(suite, IdentityEncodings.identityFor(suite)))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    // An all-zero buffer of element size: malformed on SEC1, the identity on ristretto255.
    assertThatThrownBy(() -> new VoprfClientManager(suite, new byte[suite.elementSize()]))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    assertThatThrownBy(() -> new VoprfClientManager(suite, new byte[]{0x01, 0x02}))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    assertThatThrownBy(() -> new VoprfClientManager(suite, null))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  /**
   * A server evaluating with a key other than the one the client holds must be caught. This is the
   * property the whole mode exists for.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAnEvaluationUnderADifferentKey(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail honest = detail(suite);
    VerifiableProcessorDetail rogue =
        VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "rogue");

    VoprfServerManager rogueServer = new VoprfServerManager(suite, () -> rogue);
    VoprfClientManager client = new VoprfClientManager(suite, honest.publicKey());

    VoprfClientContext context = client.hashingContext("secret");
    VerifiableEvaluatedResponse response = rogueServer.process(client.eliminationRequest(context));

    assertThatThrownBy(() -> client.hashResult(response, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  /** A tampered evaluated element must be rejected rather than silently unblinded. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAForgedEvaluatedElement(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext context = client.hashingContext("secret");
    VerifiableEvaluatedResponse honest = server.process(client.eliminationRequest(context));

    byte[] substitute = suite.groupSpec().scalarMultiply(
        suite.randomScalar(), suite.groupSpec().generator());
    VerifiableEvaluatedResponse forged = new VerifiableEvaluatedResponse(
        List.of(Hex.toHexString(substitute)), honest.proof(), honest.processIdentifier());

    assertThatThrownBy(() -> client.hashResult(forged, context))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * The response type carries no public key, structurally. If it ever gained one, a client could
   * be talked into grading a proof against a key the prover chose.
   */
  @Test
  void responseCarriesNoPublicKey() {
    List<String> components = Stream.of(VerifiableEvaluatedResponse.class.getRecordComponents())
        .map(java.lang.reflect.RecordComponent::getName).toList();
    assertThat(components).containsExactly("evaluatedPoints", "proof", "processIdentifier");
  }

  // ─── response/request binding ───────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAResponseOfTheWrongLength(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext context = client.hashingContext(List.of(
        "one".getBytes(StandardCharsets.UTF_8), "two".getBytes(StandardCharsets.UTF_8)));
    VerifiableEvaluatedResponse full = server.process(client.eliminationRequest(context));

    VerifiableEvaluatedResponse truncated = new VerifiableEvaluatedResponse(
        List.of(full.evaluatedPoints().get(0)), full.proof(), full.processIdentifier());

    assertThatThrownBy(() -> client.hashResults(truncated, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("evaluated elements");
  }

  /**
   * The attack a length check alone would miss: the server returns the right number of elements in
   * the wrong order. Accepting it would pair each input with another input's evaluation and
   * produce output that is wrong but looks entirely normal.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientRejectsAPermutedResponse(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext context = client.hashingContext(List.of(
        "one".getBytes(StandardCharsets.UTF_8), "two".getBytes(StandardCharsets.UTF_8)));
    VerifiableEvaluatedResponse honest = server.process(client.eliminationRequest(context));

    VerifiableEvaluatedResponse permuted = new VerifiableEvaluatedResponse(
        List.of(honest.evaluatedPoints().get(1), honest.evaluatedPoints().get(0)),
        honest.proof(), honest.processIdentifier());

    assertThatThrownBy(() -> client.hashResults(permuted, context))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  // ─── server-side validation ─────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void serverRejectsTheIdentityElement(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);

    // Both candidate encodings must be refused: the suite's real identity encoding, and the
    // all-zero element-sized buffer this test used to pass alone.
    assertThatThrownBy(() -> server.process(new VerifiableBlindedRequest(
        List.of(Hex.toHexString(IdentityEncodings.identityFor(suite))), "req")))
        .as("%s must refuse the identity encoding", name)
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    assertThatThrownBy(() -> server.process(new VerifiableBlindedRequest(
        List.of(Hex.toHexString(new byte[suite.elementSize()])), "req")))
        .as("%s must refuse an all-zero element-sized buffer", name)
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  /**
   * Why the suite above cannot assert a single reason, and what each suite actually guarantees.
   *
   * <p>On ristretto255 the identity is representable — 32 zero bytes is a well-formed encoding
   * that passes the RFC 9496 §4.3.1 decode checks — so refusing it is a decision about its
   * <em>value</em>, and the message says so. That is the case RFC 9497 §2.1 is written for, and
   * the one that regressed.
   *
   * <p>On the SEC1 curves the wire format is fixed-length compressed (33/49/67 bytes) and simply
   * has no encoding for the point at infinity: the 1-byte SEC1 identity fails the length check
   * and an all-zero buffer of the right length fails the prefix check. The identity is therefore
   * unrepresentable rather than rejected, and asserting an "identity" message there would be
   * asserting a reason the code has no way to reach. Pinning this keeps the distinction from
   * being quietly re-flattened into a single permissive assertion.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void identityRefusalReasonIsValueOnRistrettoAndShapeOnSec1(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    String identityHex = Hex.toHexString(IdentityEncodings.identityFor(suite));

    if (suite.elementSize() == 32) {
      assertThatThrownBy(() ->
          server.process(new VerifiableBlindedRequest(List.of(identityHex), "req")))
          .hasMessageContaining("identity");
    } else {
      assertThatThrownBy(() ->
          server.process(new VerifiableBlindedRequest(List.of(identityHex), "req")))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("must be exactly");
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void serverEnforcesTheBatchCap(String name, OprfCipherSuite suite) {
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d, 2);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext tooBig = client.hashingContext(List.of(
        "a".getBytes(StandardCharsets.UTF_8),
        "b".getBytes(StandardCharsets.UTF_8),
        "c".getBytes(StandardCharsets.UTF_8)));

    assertThatThrownBy(() -> server.process(client.eliminationRequest(tooBig)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exceeds the configured maximum");
  }

  @Test
  void serverRejectsAnUnreasonableConfiguredCap() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail d = detail(suite);

    assertThatThrownBy(() -> new VoprfServerManager(suite, () -> d, 0))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new VoprfServerManager(suite, () -> d,
        VoprfServerManager.ABSOLUTE_MAX_BATCH_SIZE + 1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * The whole batch must be evaluated under one key snapshot. Re-reading the rotating supplier per
   * element could straddle a key swap, and no single proof covers a batch split across two keys.
   */
  @Test
  void serverReadsTheKeySupplierOncePerRequest() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    AtomicInteger reads = new AtomicInteger();

    VoprfServerManager server = new VoprfServerManager(suite, () -> {
      reads.incrementAndGet();
      return d;
    });
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    List<byte[]> inputs = new ArrayList<>();
    for (int i = 0; i < 5; i++) {
      inputs.add(("input-" + i).getBytes(StandardCharsets.UTF_8));
    }
    server.process(client.eliminationRequest(client.hashingContext(inputs)));

    assertThat(reads.get()).isEqualTo(1);
  }

  @Test
  void serverRejectsKeyMaterialFromAnotherMode() {
    OprfCipherSuite verifiable = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    OprfCipherSuite partial = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();

    VerifiableProcessorDetail poprfKey =
        VerifiableProcessorDetail.derive(partial, partial.randomScalar(), "poprf-key");
    VoprfServerManager server = new VoprfServerManager(verifiable, () -> poprfKey);
    VoprfClientManager client = new VoprfClientManager(verifiable, poprfKey.publicKey());

    assertThatThrownBy(() ->
        server.process(client.eliminationRequest(client.hashingContext("x"))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("wrong mode");
  }

  /**
   * A key that has gone bad under rotation must surface as a server fault, not as a client error.
   * The HTTP adapters map {@code IllegalArgumentException} to 400, which would blame the caller
   * for a misconfiguration and present as a healthy server rejecting everyone.
   */
  @Test
  void serverSurfacesAnUnusableKeyAsAServerFault() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail good = detail(suite);
    VerifiableProcessorDetail zeroKey = new VerifiableProcessorDetail(
        BigInteger.ZERO, good.publicKey(), "rotated-bad", OprfMode.VOPRF);

    VoprfServerManager server = new VoprfServerManager(suite, () -> zeroKey);
    VoprfClientManager client = new VoprfClientManager(suite, good.publicKey());

    assertThatThrownBy(() ->
        server.process(client.eliminationRequest(client.hashingContext("x"))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("misconfigured");
  }

  // ─── key material ───────────────────────────────────────────────────────────

  /**
   * Malformed hex must not let either side choose the other's failure type. BouncyCastle's decoder
   * throws {@code DecoderException}, which extends {@link IllegalStateException} — so unwrapped, a
   * client could manufacture 5xx responses and a hostile server could bypass an application's
   * {@code SecurityException} handling.
   */
  @Test
  void malformedHexIsTypedByWhoseFaultItIs() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    // Client's fault: bad hex in the request.
    assertThatThrownBy(() ->
        server.process(new VerifiableBlindedRequest(List.of("nothexatall"), "req")))
        .isInstanceOf(IllegalArgumentException.class)
        .isNotInstanceOf(IllegalStateException.class);

    VoprfClientContext context = client.hashingContext("x");
    VerifiableEvaluatedResponse honest = server.process(client.eliminationRequest(context));

    // Server's fault: bad hex in the response, in either field.
    assertThatThrownBy(() -> client.hashResult(new VerifiableEvaluatedResponse(
        List.of("nothexatall"), honest.proof(), "k"), context))
        .isInstanceOf(SecurityException.class);
    assertThatThrownBy(() -> client.hashResult(new VerifiableEvaluatedResponse(
        honest.evaluatedPoints(), "nothexatall", "k"), context))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * A rotation that introduces a key pair whose public and secret halves do not correspond is the
   * one case startup validation structurally cannot see. It must be caught, and as a server fault.
   */
  @Test
  void serverDetectsAnInconsistentKeyPairIntroducedByRotation() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail good = detail(suite);
    VerifiableProcessorDetail broken = new VerifiableProcessorDetail(
        suite.randomScalar(), good.publicKey(), "rotated-inconsistent", OprfMode.VOPRF);

    List<VerifiableProcessorDetail> current = new ArrayList<>(List.of(good));
    VoprfServerManager server = new VoprfServerManager(suite, () -> current.get(0));
    VoprfClientManager client = new VoprfClientManager(suite, good.publicKey());

    assertThatCode(() -> server.process(client.eliminationRequest(client.hashingContext("x"))))
        .doesNotThrowAnyException();

    current.set(0, broken);
    assertThatThrownBy(() ->
        server.process(client.eliminationRequest(client.hashingContext("x"))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("inconsistent");
  }

  /** Consistency is rechecked only when the key changes, not on every request. */
  @Test
  void serverDoesNotRevalidateAnUnchangedKey() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    // A supplier returning a fresh, equal-valued instance each call — the shape that would defeat
    // reference-based caching.
    VoprfServerManager server = new VoprfServerManager(suite, () -> new VerifiableProcessorDetail(
        d.masterKey(), d.publicKey().clone(), d.processorIdentifier(), d.mode()));
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    for (int i = 0; i < 3; i++) {
      assertThatCode(() -> server.process(client.eliminationRequest(client.hashingContext("x"))))
          .doesNotThrowAnyException();
    }
  }

  /**
   * Deriving from a seed makes the one-key-per-mode rule self-enforcing: the mode byte is inside
   * {@code deriveKeyPairDst}, so the same seed cannot produce the same scalar in two modes.
   */
  @Test
  void seedDerivationYieldsADistinctKeyPerMode() {
    byte[] seed = new byte[32];
    java.util.Arrays.fill(seed, (byte) 0xa3);
    byte[] keyInfo = "test key".getBytes(StandardCharsets.UTF_8);

    for (CurveHashSuite curve : CurveHashSuite.values()) {
      OprfCipherSuite verifiable = OprfCipherSuite.builder()
          .withSuite(curve).withMode(OprfMode.VOPRF).build();
      OprfCipherSuite partial = OprfCipherSuite.builder()
          .withSuite(curve).withMode(OprfMode.POPRF).build();

      VerifiableProcessorDetail a =
          VerifiableProcessorDetail.deriveFromSeed(verifiable, seed, keyInfo, "k");
      VerifiableProcessorDetail b =
          VerifiableProcessorDetail.deriveFromSeed(partial, seed, keyInfo, "k");

      assertThat(a.masterKey()).as("%s", curve).isNotEqualTo(b.masterKey());
      assertThatCode(() -> a.validateConsistency(verifiable)).doesNotThrowAnyException();
      assertThatCode(() -> b.validateConsistency(partial)).doesNotThrowAnyException();
    }
  }

  @Test
  void detailDetectsAMismatchedKeyPair() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail honest = detail(suite);
    VerifiableProcessorDetail mismatched = new VerifiableProcessorDetail(
        suite.randomScalar(), honest.publicKey(), "mismatched", OprfMode.VOPRF);

    assertThatCode(() -> honest.validateConsistency(suite)).doesNotThrowAnyException();
    assertThatThrownBy(() -> mismatched.validateConsistency(suite))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("does not correspond");
  }

  @Test
  void detailRejectsAModeMismatch() {
    OprfCipherSuite verifiable = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    OprfCipherSuite partial = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    VerifiableProcessorDetail poprfKey =
        VerifiableProcessorDetail.derive(partial, partial.randomScalar(), "poprf");

    assertThatThrownBy(() -> poprfKey.validateConsistency(verifiable))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not serve two modes");
  }

  // ─── mode enforcement ───────────────────────────────────────────────────────

  @Test
  void managersRejectABaseModeSuite() {
    OprfCipherSuite base = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).build();
    OprfCipherSuite verifiable = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail d = detail(verifiable);

    assertThatThrownBy(() -> new VoprfServerManager(base, () -> d))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new VoprfClientManager(base, d.publicKey()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void hashResultRejectsABatchContext() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail d = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> d);
    VoprfClientManager client = new VoprfClientManager(suite, d.publicKey());

    VoprfClientContext batch = client.hashingContext(List.of(
        "a".getBytes(StandardCharsets.UTF_8), "b".getBytes(StandardCharsets.UTF_8)));
    VerifiableEvaluatedResponse response = server.process(client.eliminationRequest(batch));

    assertThatThrownBy(() -> client.hashResult(response, batch))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("single-input");
  }

  @Test
  void contextRejectsMisalignedLists() {
    assertThatThrownBy(() -> new VoprfClientContext("id",
        List.of(new byte[]{1}), List.of(BigInteger.ONE, BigInteger.TWO), List.of(new byte[]{2})))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("same length");
    assertThatThrownBy(() -> new VoprfClientContext("id", List.of(), List.of(), List.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one");
  }
}
