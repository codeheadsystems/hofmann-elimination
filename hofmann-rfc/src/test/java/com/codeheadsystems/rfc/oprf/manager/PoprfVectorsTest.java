package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.PublicInput;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * End-to-end conformance for POPRF mode against RFC 9497 Appendix A.1.3, A.3.3, A.4.3 and A.5.3.
 *
 * <p>POPRF differs from VOPRF in three places that all have to be right at once for an output to
 * match: the evaluation is an inverse multiplication under the tweaked key, the proof covers the
 * element lists in the opposite order, and the finalize transcript carries {@code info} between
 * the input and the unblinded element. Any one of them wrong still round-trips against itself.
 */
class PoprfVectorsTest {

  private static final JsonNode ROOT = load();

  private static JsonNode load() {
    try (InputStream in = PoprfVectorsTest.class.getResourceAsStream("/rfc9497/vectors.json")) {
      return new ObjectMapper().readTree(in);
    } catch (IOException e) {
      throw new IllegalStateException("Could not read rfc9497/vectors.json", e);
    }
  }

  private static final Map<String, CurveHashSuite> SUITES = Map.of(
      "ristretto255-SHA512", CurveHashSuite.RISTRETTO255_SHA512,
      "P256-SHA256", CurveHashSuite.P256_SHA256,
      "P384-SHA384", CurveHashSuite.P384_SHA384,
      "P521-SHA512", CurveHashSuite.P521_SHA512);

  record Case(String suiteName, CurveHashSuite curve, int number, int batchSize,
              byte[] skSm, byte[] pkSm, JsonNode vector) {
    @Override
    public String toString() {
      return suiteName + " vector " + number + " (batch " + batchSize + ")";
    }

    OprfCipherSuite suite() {
      return OprfCipherSuite.builder().withSuite(curve).withMode(OprfMode.POPRF).build();
    }

    List<byte[]> list(String field) {
      return Arrays.stream(vector.get(field).asText().split(",")).map(Hex::decode).toList();
    }

    byte[] info() {
      return Hex.decode(vector.get("Info").asText());
    }
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    ROOT.fieldNames().forEachRemaining(suiteName -> {
      JsonNode section = ROOT.get(suiteName).get("POPRF");
      JsonNode keys = section.get("keys");
      JsonNode vectors = section.get("vectors");
      for (int i = 0; i < vectors.size(); i++) {
        out.add(Arguments.of(new Case(
            suiteName, SUITES.get(suiteName), i + 1, vectors.get(i).get("batchSize").asInt(),
            Hex.decode(keys.get("skSm").asText()), Hex.decode(keys.get("pkSm").asText()),
            vectors.get(i))));
      }
    });
    return out.stream();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void blindedElementsMatch(Case c) {
    OprfCipherSuite suite = c.suite();
    List<byte[]> inputs = c.list("Input");
    List<byte[]> blinds = c.list("Blind");
    List<byte[]> expected = c.list("BlindedElement");

    for (int i = 0; i < c.batchSize(); i++) {
      byte[] hashed = suite.groupSpec().hashToGroup(inputs.get(i), suite.hashToGroupDst());
      BigInteger blind = suite.groupSpec().deserializeScalar(blinds.get(i));
      assertThat(Hex.toHexString(suite.groupSpec().scalarMultiply(blind, hashed)))
          .as("BlindedElement[%d]", i)
          .isEqualTo(Hex.toHexString(expected.get(i)));
    }
  }

  /**
   * The client's tweaked key {@code m*G + pkS} must equal the server's {@code (skS + m)*G}. If
   * these disagreed, every proof would fail; the RFC publishes no tweaked key directly, so the two
   * derivations are checked against each other and against the RFC's key material.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void clientAndServerDeriveTheSameTweakedKey(Case c) {
    OprfCipherSuite suite = c.suite();
    BigInteger skS = suite.groupSpec().deserializeScalar(c.skSm());
    BigInteger m = PublicInput.toScalar(suite, c.info());

    byte[] fromServer = suite.groupSpec().scalarMultiplyGenerator(
        skS.add(m).mod(suite.groupSpec().groupOrder()));
    byte[] fromClient = suite.groupSpec().linearCombinationPublic(
        new BigInteger[]{m, BigInteger.ONE},
        new byte[][]{suite.groupSpec().generator(), c.pkSm()});

    assertThat(Hex.toHexString(fromClient)).isEqualTo(Hex.toHexString(fromServer));
  }

  /** Evaluation is {@code (skS + m)^-1 * blindedElement}, not a plain multiplication. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void serverEvaluationMatches(Case c) {
    OprfCipherSuite suite = c.suite();
    BigInteger skS = suite.groupSpec().deserializeScalar(c.skSm());
    BigInteger t = skS.add(PublicInput.toScalar(suite, c.info()))
        .mod(suite.groupSpec().groupOrder());
    BigInteger tInverse = suite.scalarInverse(t);

    List<byte[]> blindedElements = c.list("BlindedElement");
    List<byte[]> expected = c.list("EvaluationElement");

    for (int i = 0; i < c.batchSize(); i++) {
      assertThat(Hex.toHexString(
          suite.groupSpec().scalarMultiply(tInverse, blindedElements.get(i))))
          .as("EvaluationElement[%d]", i)
          .isEqualTo(Hex.toHexString(expected.get(i)));
    }
  }

  /**
   * The client path through the real manager: given the RFC's evaluated elements and proof, it
   * must verify and produce the RFC's outputs — which requires the finalize transcript to carry
   * {@code info} in the right position.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void clientFinalizeMatches(Case c) {
    OprfCipherSuite suite = c.suite();
    PoprfClientManager client = new PoprfClientManager(suite, c.pkSm());

    BigInteger m = PublicInput.toScalar(suite, c.info());
    byte[] tweakedKey = suite.groupSpec().linearCombinationPublic(
        new BigInteger[]{m, BigInteger.ONE},
        new byte[][]{suite.groupSpec().generator(), c.pkSm()});

    PoprfClientContext context = new PoprfClientContext(
        "vector",
        c.list("Input"),
        c.list("Blind").stream().map(b -> suite.groupSpec().deserializeScalar(b)).toList(),
        c.list("BlindedElement"),
        c.info(),
        tweakedKey);

    PartiallyEvaluatedResponse response = new PartiallyEvaluatedResponse(
        c.list("EvaluationElement").stream().map(Hex::toHexString).toList(),
        c.vector().get("Proof").asText(),
        "rfc-vector");

    List<HashResult> results = client.hashResults(response, context);

    List<byte[]> expectedOutputs = c.list("Output");
    assertThat(results).hasSize(c.batchSize());
    for (int i = 0; i < c.batchSize(); i++) {
      assertThat(Hex.toHexString(results.get(i).hash()))
          .as("Output[%d]", i)
          .isEqualTo(Hex.toHexString(expectedOutputs.get(i)));
    }
  }

  /**
   * The full exchange through both managers with the RFC's key material and public input, using
   * freshly sampled blinds and proof randomness. The outputs must still match.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void roundTripThroughBothManagersMatchesTheRfcOutput(Case c) {
    OprfCipherSuite suite = c.suite();
    BigInteger skS = suite.groupSpec().deserializeScalar(c.skSm());
    VerifiableProcessorDetail detail = VerifiableProcessorDetail.derive(suite, skS, "rfc-vector");
    assertThat(detail.publicKey()).isEqualTo(c.pkSm());

    PoprfServerManager server = new PoprfServerManager(suite, () -> detail);
    PoprfClientManager client = new PoprfClientManager(suite, c.pkSm());

    PoprfClientContext context = client.hashingContext(c.list("Input"), c.info());
    PartiallyEvaluatedResponse response = server.process(client.eliminationRequest(context));
    List<HashResult> results = client.hashResults(response, context);

    List<byte[]> expectedOutputs = c.list("Output");
    for (int i = 0; i < c.batchSize(); i++) {
      assertThat(Hex.toHexString(results.get(i).hash()))
          .as("Output[%d]", i)
          .isEqualTo(Hex.toHexString(expectedOutputs.get(i)));
    }
  }
}
