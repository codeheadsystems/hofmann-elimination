package com.codeheadsystems.rfc.oprf.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.manager.PoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.PartiallyBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The POPRF companion to {@link RoundTripTest} — the same round trip, in RFC 9497 mode 0x02.
 *
 * <p>
 * Read {@link RoundTripTest} and then {@link VoprfRoundTripTest} first. POPRF keeps everything
 * VOPRF has — the proof, the authenticated public key, the fail-closed verification — and adds one
 * argument: a <em>public input</em>, called {@code info}, that both sides see in the clear. That is
 * what "partially oblivious" means. The input stays hidden from the server; the {@code info} does
 * not. Do not put anything confidentiality-sensitive in it.
 * </p>
 *
 * <p>
 * What the {@code info} does is select the key. The server evaluates under
 * {@code t = skS + m}, where {@code m} is a scalar derived from the {@code info}, so two different
 * public inputs are two different pseudorandom functions under one stored secret.
 * </p>
 *
 * <h2>Two ways to change the key</h2>
 *
 * <p>
 * Both are loosely "rekeying", and they are not the same operation. The section below demonstrates
 * each:
 * </p>
 *
 * <table border="1">
 *   <caption>Tweak versus rotation</caption>
 *   <tr><th></th><th>Tweak ({@code info})</th><th>Rotation ({@code skS})</th></tr>
 *   <tr><td>What changes</td><td>The effective key {@code t}</td><td>The stored secret</td></tr>
 *   <tr><td>When</td><td>Every request</td><td>A key-management event</td></tr>
 *   <tr><td>Client impact</td><td>Pass a different {@code info}</td>
 *       <td>Must be given the new {@code pkS}</td></tr>
 *   <tr><td>Cost</td><td>Free</td><td>Distribution to every client</td></tr>
 * </table>
 *
 * <p>
 * The practical consequence is that a scheme wanting per-context or per-period separation —
 * {@code "billing-2026-Q3"} then {@code "billing-2026-Q4"} — should reach for the tweak, not for
 * rotation. Rotation is for when the secret itself must be replaced.
 * </p>
 *
 * <p>
 * These assertions overlap with {@code PoprfManagerTest}, which covers the same ground plus the
 * adversarial paths. This file exists to be read.
 * </p>
 */
public class PoprfRoundTripTest {

  private static final OprfCipherSuite DEFAULT_SUITE =
      OprfCipherSuite.builder().withMode(OprfMode.POPRF).build();
  private static final String TEST_DATA = "test data for round trip";
  private static final String TEST_DATA2 = "Different Data";

  /** A realistic public input: the accounting period an evaluation belongs to. */
  private static final byte[] INFO_Q3 = "billing-2026-Q3".getBytes(StandardCharsets.UTF_8);

  /** The next period. Same server, same secret, different key. */
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

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for
   * elimination. Implements RFC 9497 OPRF mode 2 (POPRF).
   *
   * <p>
   * Still four calls. The only difference from VOPRF is that {@code info} enters at
   * {@code hashingContext} and is carried on the request, so both sides evaluate under the same
   * tweaked key.
   * </p>
   *
   * @param poprfClientManager the poprf client manager
   * @param poprfServerManager the poprf server manager
   * @param sensitiveData      the sensitive data
   * @param info               the public input, visible to the server
   * @return the string
   */
  public String convertToIdentityKey(final PoprfClientManager poprfClientManager,
                                     final PoprfServerManager poprfServerManager,
                                     final String sensitiveData,
                                     final byte[] info) {
    try (PoprfClientContext context = poprfClientManager.hashingContext(sensitiveData, info)) {
      final PartiallyBlindedRequest request = poprfClientManager.eliminationRequest(context);
      final PartiallyEvaluatedResponse response = poprfServerManager.process(request);
      final HashResult result = poprfClientManager.hashResult(response, context);
      return format(result);
    }
  }

  private static String format(final HashResult result) {
    return result.processIdentifier() + ":" + Hex.toHexString(result.hash());
  }

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
    PoprfServerManager server = new PoprfServerManager(DEFAULT_SUITE, () -> key);
    PoprfClientManager alice = new PoprfClientManager(DEFAULT_SUITE, key.publicKey());
    PoprfClientManager bob = new PoprfClientManager(DEFAULT_SUITE, key.publicKey());

    String aliceHash = convertToIdentityKey(alice, server, TEST_DATA, INFO_Q3);
    String bobHash = convertToIdentityKey(bob, server, TEST_DATA, INFO_Q3);
    String aliceHash2 = convertToIdentityKey(alice, server, TEST_DATA2, INFO_Q3);
    String bobHash2 = convertToIdentityKey(bob, server, TEST_DATA2, INFO_Q3);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
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
    PoprfServerManager server = new PoprfServerManager(suite, () -> key);
    PoprfClientManager alice = new PoprfClientManager(suite, key.publicKey());
    PoprfClientManager bob = new PoprfClientManager(suite, key.publicKey());

    String aliceHash = convertToIdentityKey(alice, server, TEST_DATA, INFO_Q3);
    String bobHash = convertToIdentityKey(bob, server, TEST_DATA, INFO_Q3);
    String aliceHash2 = convertToIdentityKey(alice, server, TEST_DATA2, INFO_Q3);
    String bobHash2 = convertToIdentityKey(bob, server, TEST_DATA2, INFO_Q3);

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

    String hash1 = convertToIdentityKey(new PoprfClientManager(suite, key1.publicKey()),
        new PoprfServerManager(suite, () -> key1), TEST_DATA, INFO_Q3);
    String hash2 = convertToIdentityKey(new PoprfClientManager(suite, key2.publicKey()),
        new PoprfServerManager(suite, () -> key2), TEST_DATA, INFO_Q3);

    assertThat(hash1).isNotEqualTo(hash2);
  }

  // ─── Two ways to change the key ─────────────────────────────────────────────

  /**
   * Rekeying by tweak: the same input, through the same server, under the same stored secret,
   * evaluates to a different value when the public input changes.
   *
   * <p>
   * Nothing was rotated. The server's {@code skS} is byte-for-byte what it was; only {@code m}
   * changed, and with it the effective key {@code t = skS + m}. Going back to the earlier
   * {@code info} reproduces the earlier value exactly, which is what makes this usable as a
   * per-period or per-tenant separation rather than a one-way ratchet.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "tweak_{0}")
  @MethodSource("allSuites")
  void differentInfoEvaluatesUnderADifferentKey(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> key);
    PoprfClientManager client = new PoprfClientManager(suite, key.publicKey());

    String q3 = convertToIdentityKey(client, server, TEST_DATA, INFO_Q3);
    String q4 = convertToIdentityKey(client, server, TEST_DATA, INFO_Q4);
    String q3Again = convertToIdentityKey(client, server, TEST_DATA, INFO_Q3);

    assertThat(q3).as("a new period is a new key").isNotEqualTo(q4);
    assertThat(q3Again).as("the old period still reproduces the old value").isEqualTo(q3);
  }

  /**
   * The tweak is binding, not advisory. A server that evaluates under a different public input than
   * the client asked for is caught rather than silently returning a different value.
   *
   * <p>
   * This is why the tweak is safe to rely on. The client derives its own tweaked key,
   * {@code m * G + pkS}, from the {@code pkS} it already trusts and the {@code info} it chose, and
   * grades the proof against that — never against anything the server sent. A server answering
   * under other {@code info} proves against a different key, and verification fails closed.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "infoBinding_{0}")
  @MethodSource("allSuites")
  void aResponseIsBoundToTheInfoTheClientAskedFor(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> key);
    PoprfClientManager client = new PoprfClientManager(suite, key.publicKey());

    try (PoprfClientContext context = client.hashingContext(TEST_DATA, INFO_Q3)) {
      PartiallyBlindedRequest honest = client.eliminationRequest(context);

      // Same blinded elements, but the server is asked to evaluate under the next period.
      PartiallyBlindedRequest substituted = new PartiallyBlindedRequest(
          honest.blindedPoints(), Hex.toHexString(INFO_Q4), honest.requestId());
      PartiallyEvaluatedResponse response = server.process(substituted);

      assertThatThrownBy(() -> client.hashResult(response, context))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("did not verify");
    }
  }

  /**
   * Rekeying by rotation: replacing the stored secret. Unlike the tweak, this is not transparent to
   * clients — they hold the public key, so rotating without redistributing it breaks them.
   *
   * <p>
   * The server reads its key material from the supplier on every request, which is the seam
   * rotation happens on: swap what the supplier returns and the next request uses the new secret.
   * An existing client, still holding the previous {@code pkS}, then fails verification. It cannot
   * do anything else — a client that accepted a proof under an unfamiliar key would have given up
   * the guarantee the mode exists to provide.
   * </p>
   *
   * <p>
   * Once the new public key reaches the client, evaluation resumes, and the output for the same
   * input under the same {@code info} has changed — which is the point of rotating, and also why a
   * batch spanning a rotation verifies against neither key.
   * </p>
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "rotation_{0}")
  @MethodSource("allSuites")
  void rotatingTheServerSecretRequiresRedistributingThePublicKey(OprfCipherSuite suite) {
    AtomicReference<VerifiableProcessorDetail> serverKey = new AtomicReference<>(detail(suite));
    PoprfServerManager server = new PoprfServerManager(suite, serverKey::get);

    PoprfClientManager client = new PoprfClientManager(suite, serverKey.get().publicKey());
    String beforeRotation = convertToIdentityKey(client, server, TEST_DATA, INFO_Q3);

    // Rotate: the very next request evaluates under a new secret.
    serverKey.set(detail(suite));

    assertThatThrownBy(() -> convertToIdentityKey(client, server, TEST_DATA, INFO_Q3))
        .as("a client holding the old public key can no longer verify")
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("did not verify");

    PoprfClientManager reissued = new PoprfClientManager(suite, serverKey.get().publicKey());
    String afterRotation = convertToIdentityKey(reissued, server, TEST_DATA, INFO_Q3);

    assertThat(afterRotation)
        .as("same input, same info, different secret — a different value")
        .isNotEqualTo(beforeRotation);
  }

  // ─── Batching ───────────────────────────────────────────────────────────────

  /**
   * One proof covers a whole batch. The batch shares a single {@code info}, because the tweaked key
   * the proof is graded against is derived from it — one key, one proof, one public input.
   *
   * @param suite the suite
   */
  @ParameterizedTest(name = "batch_{0}")
  @MethodSource("allSuites")
  void oneProofCoversABatch(OprfCipherSuite suite) {
    VerifiableProcessorDetail key = detail(suite);
    PoprfServerManager server = new PoprfServerManager(suite, () -> key);
    PoprfClientManager client = new PoprfClientManager(suite, key.publicKey());

    List<byte[]> inputs = List.of(
        "first".getBytes(StandardCharsets.UTF_8),
        "second".getBytes(StandardCharsets.UTF_8),
        "third".getBytes(StandardCharsets.UTF_8));

    List<HashResult> batched;
    try (PoprfClientContext context = client.hashingContext(inputs, INFO_Q3)) {
      PartiallyEvaluatedResponse response = server.process(client.eliminationRequest(context));
      batched = client.hashResults(response, context);
    }

    assertThat(batched).hasSize(3);
    assertThat(format(batched.get(0)))
        .isEqualTo(convertToIdentityKey(client, server, "first", INFO_Q3));
    assertThat(format(batched.get(1)))
        .isEqualTo(convertToIdentityKey(client, server, "second", INFO_Q3));
    assertThat(format(batched.get(2)))
        .isEqualTo(convertToIdentityKey(client, server, "third", INFO_Q3));
  }
}
