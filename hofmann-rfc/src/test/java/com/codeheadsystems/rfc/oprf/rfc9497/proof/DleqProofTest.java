package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Round-trip and negative coverage for the DLEQ layer. Conformance against fixed RFC bytes lives
 * in {@link DleqVectorsTest}; this file covers what the vectors cannot — the ways a proof must
 * fail.
 */
class DleqProofTest {

  static Stream<Arguments> suites() {
    List<Arguments> out = new ArrayList<>();
    for (CurveHashSuite curve : CurveHashSuite.values()) {
      out.add(Arguments.of(curve.name(),
          OprfCipherSuite.builder().withSuite(curve).withMode(OprfMode.VOPRF).build()));
    }
    return out.stream();
  }

  /** A prover-side fixture: a key, its public key, and a batch with the correct relation. */
  private record Fixture(OprfCipherSuite suite, BigInteger k, byte[] b, byte[][] c, byte[][] d) {
  }

  private static Fixture fixture(OprfCipherSuite suite, int batchSize) {
    BigInteger k = suite.randomScalar();
    byte[] b = suite.derivePublicKey(k);
    byte[][] c = new byte[batchSize][];
    byte[][] d = new byte[batchSize][];
    for (int i = 0; i < batchSize; i++) {
      c[i] = suite.groupSpec().hashToGroup(
          ("element-" + i).getBytes(StandardCharsets.UTF_8), suite.hashToGroupDst());
      d[i] = suite.groupSpec().scalarMultiply(k, c[i]);
    }
    return new Fixture(suite, k, b, c, d);
  }

  // ─── round trip ─────────────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void proofRoundTripsAtEveryBatchSize(String name, OprfCipherSuite suite) {
    for (int batch = 1; batch <= 3; batch++) {
      Fixture f = fixture(suite, batch);
      DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
      assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), f.d(), proof))
          .as("batch size %d", batch)
          .isTrue();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void proofSerializationRoundTrips(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 2);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());

    byte[] wire = proof.serialize(suite);
    assertThat(wire).hasSize(2 * suite.scalarSize());
    assertThat(DleqProof.deserialize(suite, wire)).isEqualTo(proof);
  }

  /**
   * Two proofs over identical inputs must differ, because the randomness differs. If they matched,
   * {@code r} would be being reused — and two proofs sharing {@code r} under one key expose it as
   * {@code k = (s1 - s2) / (c2 - c1)}.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void repeatedProofsUseFreshRandomness(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    DleqProof first = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    DleqProof second = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());

    assertThat(first.c()).isNotEqualTo(second.c());
    assertThat(first.s()).isNotEqualTo(second.s());
    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), f.d(), first)).isTrue();
    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), f.d(), second)).isTrue();
  }

  // ─── tampering ──────────────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void tamperedChallengeFails(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 2);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    DleqProof tampered = new DleqProof(
        proof.c().add(BigInteger.ONE).mod(suite.groupSpec().groupOrder()), proof.s());

    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), f.d(), tampered)).isFalse();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void tamperedResponseFails(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 2);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    DleqProof tampered = new DleqProof(
        proof.c(), proof.s().add(BigInteger.ONE).mod(suite.groupSpec().groupOrder()));

    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), f.d(), tampered)).isFalse();
  }

  /** The proof is graded against a public key; a different one must not accept it. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void proofFailsAgainstADifferentPublicKey(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    byte[] otherKey = suite.derivePublicKey(suite.randomScalar());

    assertThat(DleqVerifier.verifyProof(suite, otherKey, f.c(), f.d(), proof)).isFalse();
  }

  /**
   * A server that evaluates with one key cannot have that evaluation accepted against a different
   * committed key, even when it proves honestly for the key it actually used.
   * <p>
   * This is not a soundness test and cannot be one. Whether a prover <em>without</em> {@code k}
   * can forge against {@code B = k*G} rests on discrete log in the random-oracle model; no finite
   * set of cases can establish it. What tests can pin are the structural preconditions the
   * soundness argument depends on, and the surrounding cases do: the verifier recomputes {@code M}
   * and {@code Z} itself rather than accepting them (structurally — they are not in the wire
   * format), the challenge covers every transcript field, and the RFC vectors fix the transcript.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void proofFromAForeignKeyFails(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    BigInteger foreign = suite.randomScalar();
    byte[][] forged = {suite.groupSpec().scalarMultiply(foreign, f.c()[0])};
    DleqProof proof = DleqProver.generateProof(
        suite, foreign, suite.derivePublicKey(foreign), f.c(), forged);

    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), forged, proof)).isFalse();
  }

  /**
   * Reordering a batch must invalidate the proof. The composite coefficients bind the batch index
   * alongside each element pair, so a server that answered out of order — which would pair a
   * client's blind with the wrong evaluated element — cannot have its response accepted.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void reorderedBatchFails(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 2);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());

    byte[][] swappedC = {f.c()[1], f.c()[0]};
    byte[][] swappedD = {f.d()[1], f.d()[0]};

    assertThat(DleqVerifier.verifyProof(suite, f.b(), swappedC, swappedD, proof)).isFalse();
  }

  /**
   * The attack the previous test does not model: the <em>server</em> returns evaluated elements in
   * a different order than the blinded ones arrived, leaving {@code C} untouched and permuting
   * only {@code D}. A client that accepted this would unblind {@code evaluated[1]} with
   * {@code blind[0]} and derive two silently wrong outputs.
   * <p>
   * It fails because {@code d_i = H(seed, i, C[i], D[i])} binds the two lists positionally, so a
   * permutation of one changes every coefficient.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void batchWithOnlyTheEvaluatedListPermutedFails(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 2);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    byte[][] permutedD = {f.d()[1], f.d()[0]};

    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), permutedD, proof)).isFalse();
  }

  /**
   * A proof generated under one mode must not verify under another, even with identical key and
   * elements. This pins that {@code contextString} really reaches {@code seedDst}, {@code d_i} and
   * the challenge, rather than only the key derivation where the vectors already prove it.
   */
  @Test
  void proofDoesNotVerifyAcrossModes() {
    for (CurveHashSuite curve : CurveHashSuite.values()) {
      OprfCipherSuite verifiable = OprfCipherSuite.builder()
          .withSuite(curve).withMode(OprfMode.VOPRF).build();
      OprfCipherSuite partial = OprfCipherSuite.builder()
          .withSuite(curve).withMode(OprfMode.POPRF).build();

      Fixture f = fixture(verifiable, 1);
      DleqProof proof = DleqProver.generateProof(verifiable, f.k(), f.b(), f.c(), f.d());

      assertThat(DleqVerifier.verifyProof(verifiable, f.b(), f.c(), f.d(), proof))
          .as("%s same mode", curve).isTrue();
      assertThat(DleqVerifier.verifyProof(partial, f.b(), f.c(), f.d(), proof))
          .as("%s cross mode", curve).isFalse();
    }
  }

  /** The DLEQ layer is never instantiated in base mode; using a base-mode suite is a bug. */
  @Test
  void baseModeSuiteIsRejected() {
    OprfCipherSuite base = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.OPRF).build();
    OprfCipherSuite verifiable = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    Fixture f = fixture(verifiable, 1);

    assertThatThrownBy(() -> DleqProver.generateProof(base, f.k(), f.b(), f.c(), f.d()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> DleqVerifier.verifyProof(base, f.b(), f.c(), f.d(),
        new DleqProof(BigInteger.ONE, BigInteger.ONE)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /** A proof is bound to its batch and cannot be replayed against a different one. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void proofDoesNotTransferToAnotherBatch(String name, OprfCipherSuite suite) {
    Fixture first = fixture(suite, 1);
    DleqProof proof = DleqProver.generateProof(suite, first.k(), first.b(), first.c(), first.d());

    byte[] other = suite.groupSpec().hashToGroup(
        "unrelated".getBytes(StandardCharsets.UTF_8), suite.hashToGroupDst());
    byte[][] otherC = {other};
    byte[][] otherD = {suite.groupSpec().scalarMultiply(first.k(), other)};

    assertThat(DleqVerifier.verifyProof(suite, first.b(), otherC, otherD, proof)).isFalse();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void mismatchedEvaluationFails(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    byte[][] wrongD = {suite.groupSpec().scalarMultiply(suite.randomScalar(), f.c()[0])};

    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), wrongD, proof)).isFalse();
  }

  @Test
  void nullProofFails() {
    OprfCipherSuite suite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    Fixture f = fixture(suite, 1);
    assertThat(DleqVerifier.verifyProof(suite, f.b(), f.c(), f.d(), null)).isFalse();
  }

  // ─── malformed encodings ────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void deserializeRejectsWrongLength(String name, OprfCipherSuite suite) {
    int ns = suite.scalarSize();
    assertThatThrownBy(() -> DleqProof.deserialize(suite, new byte[2 * ns - 1]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> DleqProof.deserialize(suite, new byte[2 * ns + 1]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> DleqProof.deserialize(suite, null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * Non-canonical scalars must not parse. Otherwise {@code c} and {@code c + n} would be distinct
   * byte strings that both verify, making the proof encoding malleable.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void deserializeRejectsNonCanonicalScalars(String name, OprfCipherSuite suite) {
    byte[] allOnes = new byte[2 * suite.scalarSize()];
    java.util.Arrays.fill(allOnes, (byte) 0xff);
    assertThatThrownBy(() -> DleqProof.deserialize(suite, allOnes))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("canonical");
  }

  /** A zero challenge and zero response make {@code t2} the identity; that must not verify. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void zeroScalarsDoNotVerify(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    assertThat(DleqVerifier.verifyProof(
        suite, f.b(), f.c(), f.d(), new DleqProof(BigInteger.ZERO, BigInteger.ZERO)))
        .isFalse();
  }

  // ─── batch bounds ───────────────────────────────────────────────────────────

  /**
   * Batch-shape problems throw rather than returning {@code false}, on both sides. They are caller
   * bugs, not proof failures — most importantly the case where a manager forgets to check that the
   * server returned as many evaluated elements as it was sent — and reporting them as "the proof
   * did not verify" would hide the defect behind a plausible-looking rejection.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void emptyBatchIsRejected(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    assertThatThrownBy(() -> DleqProver.generateProof(
        suite, f.k(), f.b(), new byte[0][], new byte[0][]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one");

    assertThatThrownBy(() -> DleqVerifier.verifyProof(suite, f.b(), new byte[0][], new byte[0][],
        new DleqProof(BigInteger.ONE, BigInteger.ONE)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void mismatchedListLengthsAreRejected(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 2);
    byte[][] shortD = {f.d()[0]};

    assertThatThrownBy(() -> DleqProver.generateProof(suite, f.k(), f.b(), f.c(), shortD))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("same length");

    DleqProof proof = DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d());
    assertThatThrownBy(() -> DleqVerifier.verifyProof(suite, f.b(), f.c(), shortD, proof))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("same length");
  }

  // ─── proof randomness ───────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void proverRejectsOutOfRangeRandomness(String name, OprfCipherSuite suite) {
    Fixture f = fixture(suite, 1);
    BigInteger n = suite.groupSpec().groupOrder();

    for (BigInteger bad : List.of(BigInteger.ZERO, n, n.add(BigInteger.ONE))) {
      assertThatThrownBy(() -> DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d(), bad))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("[1, n-1]");
    }
    assertThatThrownBy(() -> DleqProver.generateProof(suite, f.k(), f.b(), f.c(), f.d(),
        BigInteger.ONE.negate()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * The deterministic-randomness overload exists only to reproduce the Appendix A
   * {@code ProofRandomScalar} values. It must stay package-private, and no production code may
   * reach for it — a caller that supplies {@code r} owns the one input whose reuse hands over the
   * server's long-term key.
   */
  @Test
  void deterministicRandomnessOverloadIsNotPublic() throws NoSuchMethodException {
    Method method = DleqProver.class.getDeclaredMethod("generateProof",
        OprfCipherSuite.class, BigInteger.class, byte[].class,
        byte[][].class, byte[][].class, BigInteger.class);

    assertThat(Modifier.isPublic(method.getModifiers()))
        .as("the explicit-randomness overload must not be public")
        .isFalse();
  }

  /**
   * Structural guard on the seam that matters: no production code outside this package may supply
   * its own proof randomness.
   * <p>
   * Scoped to the six-argument form on purpose. Managers are expected to call the public five-
   * argument {@code generateProof}, so a blanket ban on the name would fire on legitimate callers
   * and get deleted — taking the real guard with it. Package-private access already stops the
   * six-argument form compiling from elsewhere; this catches the case where someone moves a class
   * into this package and thereby acquires access to it silently, since a proof built with a
   * caller-supplied {@code r} looks entirely valid.
   */
  @Test
  void noProductionCodeSuppliesItsOwnProofRandomness() throws IOException {
    Path main = Path.of("src/main/java");
    Path proofPackage = main.resolve("com/codeheadsystems/rfc/oprf/rfc9497/proof");
    // generateProof( ... , ... , ... , ... , ... , r) — six comma-separated arguments.
    Pattern sixArgCall = Pattern.compile(
        "generateProof\\s*\\((?:[^()]|\\([^()]*\\))*?,(?:[^()]|\\([^()]*\\))*?,"
            + "(?:[^()]|\\([^()]*\\))*?,(?:[^()]|\\([^()]*\\))*?,(?:[^()]|\\([^()]*\\))*?,",
        Pattern.DOTALL);

    try (Stream<Path> files = Files.walk(main)) {
      List<String> offenders = files
          .filter(p -> p.toString().endsWith(".java"))
          .filter(p -> !p.startsWith(proofPackage))
          .filter(p -> {
            try {
              return sixArgCall.matcher(Files.readString(p)).find();
            } catch (IOException e) {
              throw new IllegalStateException(e);
            }
          })
          .map(Path::toString)
          .toList();

      assertThat(offenders)
          .as("only the proof package may supply proof randomness")
          .isEmpty();
    }
  }
}
