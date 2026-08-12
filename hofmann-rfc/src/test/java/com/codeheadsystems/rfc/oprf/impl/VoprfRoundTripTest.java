package com.codeheadsystems.rfc.oprf.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.manager.VoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.VerifiableBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The VOPRF companion to {@link RoundTripTest} — the same round trip, in RFC 9497 mode 0x01.
 *
 * <p>
 * Read {@link RoundTripTest} first. The shape here is identical: blind, send, evaluate, unblind.
 * What VOPRF adds is a single step the client cannot skip — it verifies a proof that the server
 * evaluated with the key it publicly committed to.
 * </p>
 *
 * <p>
 * That matters because base mode gives the client no way to check. A server answering with the
 * wrong key, or with a garbage element, produces output a base-mode client cannot distinguish from
 * correct: it is a well-formed hash of the right shape, just not the right value. The client finds
 * out when something downstream fails to match, which may be never.
 * {@link #clientRejectsAnEvaluationFromAnImpostorServer} is that scenario, caught.
 * </p>
 *
 * <p>
 * The price is that the client must hold the server's public key <em>and have authenticated it out
 * of band</em>. The response type deliberately has no field for one — a key travelling with the
 * proof it authenticates would let the server pick the standard it is judged against, and every
 * response would verify.
 * </p>
 *
 * <p>
 * These assertions overlap with {@code VoprfManagerTest}, which covers the same ground plus the
 * adversarial paths. This file exists to be read.
 * </p>
 */
public class VoprfRoundTripTest {

  private static final OprfCipherSuite DEFAULT_SUITE =
      OprfCipherSuite.builder().withMode(OprfMode.VOPRF).build();
  private static final String TEST_DATA = "test data for round trip";
  private static final String TEST_DATA2 = "Different Data";

  /**
   * All suites stream.
   *
   * @return the stream
   */
  static Stream<OprfCipherSuite> allSuites() {
    return Stream.of(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build(),
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P384_SHA384).withMode(OprfMode.VOPRF).build(),
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P521_SHA512).withMode(OprfMode.VOPRF).build(),
        OprfCipherSuite.builder().withSuite(CurveHashSuite.RISTRETTO255_SHA512).withMode(OprfMode.VOPRF).build()
    );
  }

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for
   * elimination. Implements RFC 9497 OPRF mode 1 (VOPRF).
   *
   * <p>
   * The four calls are the same as base mode. The verification is not a fifth step: it happens
   * inside {@code hashResult}, which either returns a hash that was proved correct or throws. There
   * is no way to obtain an unverified result through this API.
   * </p>
   *
   * @param voprfClientManager the voprf client manager
   * @param voprfServerManager the voprf server manager
   * @param sensitiveData      the sensitive data
   * @return the string
   */
  public String convertToIdentityKey(final VoprfClientManager voprfClientManager,
                                     final VoprfServerManager voprfServerManager,
                                     final String sensitiveData) {
    // The context holds the client's copy of the input and its blinding scalars; closing it zeroes
    // the copy. Scope the block to the whole exchange — a closed context refuses to be used.
    try (VoprfClientContext context = voprfClientManager.hashingContext(sensitiveData)) {
      final VerifiableBlindedRequest request = voprfClientManager.eliminationRequest(context);
      final VerifiableEvaluatedResponse response = voprfServerManager.process(request);
      final HashResult result = voprfClientManager.hashResult(response, context);
      return format(result);
    }
  }

  private static String format(final HashResult result) {
    return result.processIdentifier() + ":" + Hex.toHexString(result.hash());
  }

  /**
   * Server key material. {@code derive} computes the public key from the secret, so the pair cannot
   * disagree — assembling one by hand with a mismatched public key yields proofs that are
   * internally consistent and verify for nobody, forever.
   */
  private static VerifiableProcessorDetail detail(final OprfCipherSuite suite) {
    return VerifiableProcessorDetail.derive(suite, suite.randomScalar(), "SP:" + UUID.randomUUID());
  }

  // ─── Round trip ─────────────────────────────────────────────────────────────

  /**
   * Test round trip.
   */
  @Test
  void testRoundTrip() {
    VerifiableProcessorDetail key = detail(DEFAULT_SUITE);
    VoprfServerManager server = new VoprfServerManager(DEFAULT_SUITE, () -> key);
    VoprfClientManager alice = new VoprfClientManager(DEFAULT_SUITE, key.publicKey());
    VoprfClientManager bob = new VoprfClientManager(DEFAULT_SUITE, key.publicKey());

    String aliceHash = convertToIdentityKey(alice, server, TEST_DATA);
    String bobHash = convertToIdentityKey(bob, server, TEST_DATA);
    String aliceHash2 = convertToIdentityKey(alice, server, TEST_DATA2);
    String bobHash2 = convertToIdentityKey(bob, server, TEST_DATA2);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
  }

  /**
   * Test different servers have different results.
   */
  @Test
  void testDifferentServersHaveDifferentResults() {
    VerifiableProcessorDetail key1 = detail(DEFAULT_SUITE);
    VerifiableProcessorDetail key2 = detail(DEFAULT_SUITE);
    VoprfServerManager server1 = new VoprfServerManager(DEFAULT_SUITE, () -> key1);
    VoprfServerManager server2 = new VoprfServerManager(DEFAULT_SUITE, () -> key2);

    String hash1 = convertToIdentityKey(
        new VoprfClientManager(DEFAULT_SUITE, key1.publicKey()), server1, TEST_DATA);
    String hash2 = convertToIdentityKey(
        new VoprfClientManager(DEFAULT_SUITE, key2.publicKey()), server2, TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }

  /**
   * Round trip all suites.
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "roundTrip_{0}")
  @MethodSource("allSuites")
  void roundTripAllSuites(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> key);
    VoprfClientManager alice = new VoprfClientManager(suite, key.publicKey());
    VoprfClientManager bob = new VoprfClientManager(suite, key.publicKey());

    String aliceHash = convertToIdentityKey(alice, server, TEST_DATA);
    String bobHash = convertToIdentityKey(bob, server, TEST_DATA);
    String aliceHash2 = convertToIdentityKey(alice, server, TEST_DATA2);
    String bobHash2 = convertToIdentityKey(bob, server, TEST_DATA2);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
  }

  /**
   * Different servers have different results all suites.
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "differentServers_{0}")
  @MethodSource("allSuites")
  void differentServersHaveDifferentResultsAllSuites(OprfCipherSuite suite) {
    VerifiableProcessorDetail key1 = detail(suite);
    VerifiableProcessorDetail key2 = detail(suite);

    String hash1 = convertToIdentityKey(new VoprfClientManager(suite, key1.publicKey()),
        new VoprfServerManager(suite, () -> key1), TEST_DATA);
    String hash2 = convertToIdentityKey(new VoprfClientManager(suite, key2.publicKey()),
        new VoprfServerManager(suite, () -> key2), TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }

  // ─── What VOPRF buys you ────────────────────────────────────────────────────

  /**
   * The point of the mode. A client configured with one server's public key is answered by a
   * different server, holding a different key. The evaluation is perfectly well formed — it is
   * simply not the function the client asked for — and the proof is the only thing that reveals it.
   *
   * <p>
   * In base mode this substitution succeeds silently: {@code RoundTripTest} shows two servers
   * producing different hashes for the same input, and a base-mode client has no way to tell which
   * of the two it is talking to.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "impostorRejected_{0}")
  @MethodSource("allSuites")
  void clientRejectsAnEvaluationFromAnImpostorServer(OprfCipherSuite suite) {
    VerifiableProcessorDetail honest = detail(suite);
    VerifiableProcessorDetail impostor = detail(suite);

    VoprfServerManager impostorServer = new VoprfServerManager(suite, () -> impostor);
    VoprfClientManager client = new VoprfClientManager(suite, honest.publicKey());

    assertThatThrownBy(() -> convertToIdentityKey(client, impostorServer, TEST_DATA))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");
  }

  // ─── Batching ───────────────────────────────────────────────────────────────

  /**
   * One proof covers a whole batch, and the results line up with the inputs by position.
   *
   * <p>
   * The proof is a batched Chaum-Pedersen DLEQ: it attests that one key relates every evaluated
   * element to its blinded counterpart. That binding is what makes reordering detectable — the
   * composite coefficients tie each element pair to its index — so a permuted response fails
   * verification rather than silently returning the right hashes against the wrong inputs.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "batch_{0}")
  @MethodSource("allSuites")
  void oneProofCoversABatch(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    VoprfServerManager server = new VoprfServerManager(suite, () -> key);
    VoprfClientManager client = new VoprfClientManager(suite, key.publicKey());

    List<byte[]> inputs = List.of(
        "first".getBytes(StandardCharsets.UTF_8),
        "second".getBytes(StandardCharsets.UTF_8),
        "third".getBytes(StandardCharsets.UTF_8));

    List<HashResult> batched;
    try (VoprfClientContext context = client.hashingContext(inputs)) {
      VerifiableEvaluatedResponse response = server.process(client.eliminationRequest(context));
      batched = client.hashResults(response, context);
    }

    assertThat(batched).hasSize(3);
    assertThat(format(batched.get(0))).isEqualTo(convertToIdentityKey(client, server, "first"));
    assertThat(format(batched.get(1))).isEqualTo(convertToIdentityKey(client, server, "second"));
    assertThat(format(batched.get(2))).isEqualTo(convertToIdentityKey(client, server, "third"));
  }
}
