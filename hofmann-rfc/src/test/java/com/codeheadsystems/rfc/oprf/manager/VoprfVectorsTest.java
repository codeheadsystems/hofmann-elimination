package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
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
 * End-to-end conformance for VOPRF mode against RFC 9497 Appendix A.1.2, A.3.2, A.4.2 and A.5.2.
 *
 * <p>The DLEQ layer is already pinned to the RFC's proof bytes; what these add is the rest of the
 * exchange — that a given input and blind produce the RFC's blinded element, that the server's
 * evaluation matches, and that the client's finalize produces the RFC's output. Together they
 * establish the whole protocol against fixed bytes rather than against itself.
 *
 * <p>The blinds have to be injected, since the client would otherwise sample its own. That is done
 * by driving the suite primitives directly for the blinding step and then handing the resulting
 * context to the real client manager for verification and finalization, so the code under test is
 * the manager's own proof-checking and unblinding path.
 */
class VoprfVectorsTest {

  private static final JsonNode ROOT = load();

  private static JsonNode load() {
    try (InputStream in = VoprfVectorsTest.class.getResourceAsStream("/rfc9497/vectors.json")) {
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
      return OprfCipherSuite.builder().withSuite(curve).withMode(OprfMode.VOPRF).build();
    }

    List<byte[]> list(String field) {
      return Arrays.stream(vector.get(field).asText().split(",")).map(Hex::decode).toList();
    }
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    ROOT.fieldNames().forEachRemaining(suiteName -> {
      JsonNode section = ROOT.get(suiteName).get("VOPRF");
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

  /** Blinding: {@code blindedElement = blind * HashToGroup(input)}. */
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
   * The evaluation step alone: {@code evaluatedElement = skS * blindedElement}. Checked at the
   * group level rather than through {@link VoprfServerManager}, because the manager also emits a
   * proof under its own randomness and so cannot be compared against fixed bytes here. The manager
   * itself is covered by {@link #roundTripThroughBothManagersMatchesTheRfcOutput}.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void serverEvaluationMatches(Case c) {
    OprfCipherSuite suite = c.suite();
    BigInteger skS = suite.groupSpec().deserializeScalar(c.skSm());
    List<byte[]> blindedElements = c.list("BlindedElement");
    List<byte[]> expected = c.list("EvaluationElement");

    for (int i = 0; i < c.batchSize(); i++) {
      assertThat(Hex.toHexString(
          suite.groupSpec().scalarMultiply(skS, blindedElements.get(i))))
          .as("EvaluationElement[%d]", i)
          .isEqualTo(Hex.toHexString(expected.get(i)));
    }
  }

  /**
   * The client path end to end, through the real manager: given the RFC's evaluated elements and
   * proof, the manager must verify the proof and produce the RFC's outputs.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void clientFinalizeMatches(Case c) {
    OprfCipherSuite suite = c.suite();
    VoprfClientManager client = new VoprfClientManager(suite, c.pkSm());

    List<byte[]> inputs = c.list("Input");
    List<BigInteger> blinds = c.list("Blind").stream()
        .map(b -> suite.groupSpec().deserializeScalar(b)).toList();
    List<byte[]> blindedElements = c.list("BlindedElement");
    List<byte[]> expectedOutputs = c.list("Output");

    var context = new com.codeheadsystems.rfc.oprf.model.VoprfClientContext(
        "vector", inputs, blinds, blindedElements);
    var response = new VerifiableEvaluatedResponse(
        c.list("EvaluationElement").stream().map(Hex::toHexString).toList(),
        c.vector().get("Proof").asText(),
        "rfc-vector");

    List<HashResult> results = client.hashResults(response, context);

    assertThat(results).hasSize(c.batchSize());
    for (int i = 0; i < c.batchSize(); i++) {
      assertThat(Hex.toHexString(results.get(i).hash()))
          .as("Output[%d]", i)
          .isEqualTo(Hex.toHexString(expectedOutputs.get(i)));
    }
  }

  /**
   * The full exchange through both managers with the RFC's key material, using freshly sampled
   * blinds and proof randomness. The outputs must still match the RFC, because neither the blind
   * nor the proof randomness affects the OPRF output.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void roundTripThroughBothManagersMatchesTheRfcOutput(Case c) {
    OprfCipherSuite suite = c.suite();
    BigInteger skS = suite.groupSpec().deserializeScalar(c.skSm());
    VerifiableProcessorDetail detail =
        VerifiableProcessorDetail.derive(suite, skS, "rfc-vector");
    detail.validateConsistency(suite);
    assertThat(detail.publicKey()).isEqualTo(c.pkSm());

    VoprfServerManager server = new VoprfServerManager(suite, () -> detail);
    VoprfClientManager client = new VoprfClientManager(suite, c.pkSm());

    var context = client.hashingContext(c.list("Input"));
    var response = server.process(client.eliminationRequest(context));
    List<HashResult> results = client.hashResults(response, context);

    List<byte[]> expectedOutputs = c.list("Output");
    for (int i = 0; i < c.batchSize(); i++) {
      assertThat(Hex.toHexString(results.get(i).hash()))
          .as("Output[%d]", i)
          .isEqualTo(Hex.toHexString(expectedOutputs.get(i)));
    }
  }
}
