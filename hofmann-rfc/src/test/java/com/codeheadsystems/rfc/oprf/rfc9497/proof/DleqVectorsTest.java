package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Checks the DLEQ layer against the RFC 9497 Appendix A vectors.
 *
 * <p>These are the tests that matter for this layer. A prover and verifier written from the same
 * misreading interoperate perfectly with each other, so a round-trip test cannot detect a wrong
 * domain-separation tag, a reversed {@code [c, s]} encoding, a missing length prefix, or a
 * transcript field in the wrong order. Only fixed expected bytes can, and Appendix A supplies them
 * along with the {@code ProofRandomScalar} needed to make proof generation deterministic.
 *
 * <p>Both verifiable modes are covered because they exercise the same code with the element lists
 * <em>swapped</em>: VOPRF proves over {@code (blinded, evaluated)} while POPRF proves over
 * {@code (evaluated, blinded)}. A shared implementation that hardcoded either order would still
 * round-trip, and would still pass one mode's vectors while failing the other's.
 */
class DleqVectorsTest {

  static Stream<Rfc9497Vectors.Vector> voprfVectors() {
    return Rfc9497Vectors.forMode(OprfMode.VOPRF).stream();
  }

  static Stream<Rfc9497Vectors.Vector> poprfVectors() {
    return Rfc9497Vectors.forMode(OprfMode.POPRF).stream();
  }

  /**
   * VOPRF (§3.3.2): the proof is generated with {@code k = skS}, {@code B = pkS}, and the element
   * lists in the order {@code (blindedElements, evaluatedElements)}.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("voprfVectors")
  void voprfProofMatchesTheRfc(Rfc9497Vectors.Vector v) {
    OprfCipherSuite suite = v.suite();
    BigInteger skS = suite.groupSpec().deserializeScalar(v.skSm());
    BigInteger r = suite.groupSpec().deserializeScalar(v.bytes("ProofRandomScalar"));

    DleqProof proof = DleqProver.generateProof(
        suite, skS, v.pkSm(), v.list("BlindedElement"), v.list("EvaluationElement"), r);

    assertThat(Hex.toHexString(proof.serialize(suite)))
        .as("Proof")
        .isEqualTo(Hex.toHexString(v.bytes("Proof")));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("voprfVectors")
  void voprfProofFromTheRfcVerifies(Rfc9497Vectors.Vector v) {
    OprfCipherSuite suite = v.suite();
    DleqProof proof = DleqProof.deserialize(suite, v.bytes("Proof"));

    assertThat(DleqVerifier.verifyProof(
        suite, v.pkSm(), v.list("BlindedElement"), v.list("EvaluationElement"), proof))
        .isTrue();
  }

  /**
   * POPRF (§3.3.3): the proof is generated with the tweaked key {@code t = skS + m}, with
   * {@code B = t * G}, and with the element lists <em>reversed</em> — {@code (evaluated, blinded)}
   * — because there the relation runs {@code blinded = t * evaluated}.
   *
   * <p>The tweak is computed inline here rather than through a manager, since the POPRF protocol
   * layer does not exist yet. Phase 4 will own this derivation; what it is doing for now is
   * feeding the DLEQ layer a case with the element order swapped.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("poprfVectors")
  void poprfProofMatchesTheRfc(Rfc9497Vectors.Vector v) {
    OprfCipherSuite suite = v.suite();
    BigInteger t = tweakedKey(suite, v);
    byte[] tweakedPublicKey = suite.groupSpec().scalarMultiplyGenerator(t);
    BigInteger r = suite.groupSpec().deserializeScalar(v.bytes("ProofRandomScalar"));

    DleqProof proof = DleqProver.generateProof(
        suite, t, tweakedPublicKey, v.list("EvaluationElement"), v.list("BlindedElement"), r);

    assertThat(Hex.toHexString(proof.serialize(suite)))
        .as("Proof")
        .isEqualTo(Hex.toHexString(v.bytes("Proof")));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("poprfVectors")
  void poprfProofFromTheRfcVerifies(Rfc9497Vectors.Vector v) {
    OprfCipherSuite suite = v.suite();
    byte[] tweakedPublicKey = suite.groupSpec().scalarMultiplyGenerator(tweakedKey(suite, v));
    DleqProof proof = DleqProof.deserialize(suite, v.bytes("Proof"));

    assertThat(DleqVerifier.verifyProof(
        suite, tweakedPublicKey, v.list("EvaluationElement"), v.list("BlindedElement"), proof))
        .isTrue();
  }

  /**
   * Swapping the element lists must break verification. This is what pins the ordering as a real
   * property rather than a convention the implementation shares with itself: the coefficients
   * {@code d_i} bind {@code C[i]} and {@code D[i]} in a fixed order inside the composite
   * transcript, so exchanging them yields different composites and a different challenge.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("voprfVectors")
  void voprfProofDoesNotVerifyWithTheListsSwapped(Rfc9497Vectors.Vector v) {
    OprfCipherSuite suite = v.suite();
    DleqProof proof = DleqProof.deserialize(suite, v.bytes("Proof"));

    assertThat(DleqVerifier.verifyProof(
        suite, v.pkSm(), v.list("EvaluationElement"), v.list("BlindedElement"), proof))
        .isFalse();
  }

  /** Confirms the vector file's own key material derives from its seed, on every suite and mode. */
  @ParameterizedTest(name = "{0}")
  @MethodSource({"voprfVectors", "poprfVectors"})
  void vectorKeyMaterialIsSelfConsistent(Rfc9497Vectors.Vector v) {
    OprfCipherSuite suite = v.suite();
    BigInteger skS = suite.deriveKeyPair(v.seed(), v.keyInfo());

    assertThat(suite.groupSpec().serializeScalar(skS)).isEqualTo(v.skSm());
    assertThat(suite.derivePublicKey(skS)).isEqualTo(v.pkSm());
  }

  /** Sanity check that the loader found every vector the RFC publishes for the proof modes. */
  @org.junit.jupiter.api.Test
  void everyVerifiableVectorIsLoaded() {
    List<Rfc9497Vectors.Vector> voprf = Rfc9497Vectors.forMode(OprfMode.VOPRF);
    List<Rfc9497Vectors.Vector> poprf = Rfc9497Vectors.forMode(OprfMode.POPRF);

    // Four suites, three vectors each: two at batch size 1, one at batch size 2.
    assertThat(voprf).hasSize(12);
    assertThat(poprf).hasSize(12);
    assertThat(voprf.stream().filter(v -> v.batchSize() == 2)).hasSize(4);
    assertThat(poprf.stream().filter(v -> v.batchSize() == 2)).hasSize(4);
  }

  /**
   * {@code t = skS + m} where {@code m = HashToScalar("Info" || I2OSP(len(info), 2) || info)},
   * per RFC 9497 §3.3.3.
   */
  private static BigInteger tweakedKey(OprfCipherSuite suite, Rfc9497Vectors.Vector v) {
    byte[] info = v.bytes("Info");
    byte[] framedInfo = ByteUtils.concat(
        "Info".getBytes(StandardCharsets.UTF_8),
        ByteUtils.I2OSP(info.length, 2),
        info);
    BigInteger m = suite.hashToScalar(framedInfo, suite.hashToScalarDst());
    BigInteger skS = suite.groupSpec().deserializeScalar(v.skSm());
    return skS.add(m).mod(suite.groupSpec().groupOrder());
  }
}
