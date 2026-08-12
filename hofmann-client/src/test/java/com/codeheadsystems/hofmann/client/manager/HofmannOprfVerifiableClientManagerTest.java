package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.codeheadsystems.rfc.oprf.manager.PoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * End-to-end verifiable-mode behaviour of the client manager, with the accessor mocked but the
 * server side <strong>real</strong>.
 *
 * <p>Stubbing the server's response with fixture bytes would test only plumbing. A DLEQ proof is
 * the one thing here that notices a mangled batch order, a re-encoded element or a suite built
 * under the wrong mode, and it only notices if a real prover produced it. So the mock accessor
 * hands each request to an actual {@code VoprfServerManager} / {@code PoprfServerManager} keyed to
 * the same secret the client pins, and the assertions are on what verification does with the
 * result.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOprfVerifiableClientManagerTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final BigInteger VOPRF_KEY = new BigInteger("42424242424242424242424242", 16);
  private static final BigInteger POPRF_KEY = new BigInteger("5353535353535353535353535353", 16);
  private static final byte[] INPUT_A = "input-alpha".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INPUT_B = "input-beta".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INFO = "tenant-a".getBytes(StandardCharsets.UTF_8);

  @Mock private HofmannOprfAccessor accessor;

  private OprfCipherSuite voprfSuite;
  private OprfCipherSuite poprfSuite;
  private VerifiableProcessorDetail voprfDetail;
  private VerifiableProcessorDetail poprfDetail;
  private VoprfServerManager voprfServer;
  private PoprfServerManager poprfServer;
  private HofmannOprfClientManager manager;

  @BeforeEach
  void setUp() {
    voprfSuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    poprfSuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    voprfDetail = VerifiableProcessorDetail.derive(voprfSuite, VOPRF_KEY, "proc-voprf");
    poprfDetail = VerifiableProcessorDetail.derive(poprfSuite, POPRF_KEY, "proc-poprf");
    voprfServer = new VoprfServerManager(voprfSuite, () -> voprfDetail);
    poprfServer = new PoprfServerManager(poprfSuite, () -> poprfDetail);

    manager = new HofmannOprfClientManager(accessor,
        new VoprfClientManager(voprfSuite, voprfDetail.publicKey()),
        new PoprfClientManager(poprfSuite, poprfDetail.publicKey()));
  }

  private void serveVoprf() {
    when(accessor.handleVerifiableRequest(eq(SERVER_ID), any(VoprfRequest.class)))
        .thenAnswer(inv -> new VoprfResponse(
            voprfServer.process(inv.getArgument(1, VoprfRequest.class).blindedRequest())));
  }

  private void servePoprf() {
    when(accessor.handlePartiallyObliviousRequest(eq(SERVER_ID), any(PoprfRequest.class)))
        .thenAnswer(inv -> new PoprfResponse(
            poprfServer.process(inv.getArgument(1, PoprfRequest.class).blindedRequest())));
  }

  // ─── VOPRF ─────────────────────────────────────────────────────────────────

  @Test
  void performVerifiableHash_singleInput_roundTripsAndVerifies() {
    serveVoprf();

    HofmannHashResult result = manager.performVerifiableHash(INPUT_A, SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("proc-voprf");
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  /**
   * The batch is the point of the mode: one proof covers all of it. The results must be
   * index-aligned with the inputs, which a proof does not check — reordering the outputs would
   * still verify.
   */
  @Test
  void performVerifiableHash_batch_returnsOneResultPerInputInOrder() {
    serveVoprf();

    List<HofmannHashResult> batch =
        manager.performVerifiableHash(List.of(INPUT_A, INPUT_B), SERVER_ID);
    HofmannHashResult soloA = manager.performVerifiableHash(INPUT_A, SERVER_ID);
    HofmannHashResult soloB = manager.performVerifiableHash(INPUT_B, SERVER_ID);

    assertThat(batch).hasSize(2);
    assertThat(batch.get(0).hash()).isEqualTo(soloA.hash());
    assertThat(batch.get(1).hash()).isEqualTo(soloB.hash());
    assertThat(batch.get(0).hash()).isNotEqualTo(batch.get(1).hash());
  }

  @Test
  void performVerifiableHash_batch_sharesRequestIdAndProcessIdentifier() {
    serveVoprf();

    List<HofmannHashResult> batch =
        manager.performVerifiableHash(List.of(INPUT_A, INPUT_B), SERVER_ID);

    assertThat(batch.get(0).requestId()).isEqualTo(batch.get(1).requestId());
    assertThat(batch.get(0).processIdentifier()).isEqualTo(batch.get(1).processIdentifier());
  }

  @Test
  void performVerifiableHash_isDeterministicForTheSameInputAndKey() {
    serveVoprf();

    assertThat(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
  }

  @Test
  void performVerifiableHash_stringOverload_matchesTheByteArrayOverload() {
    serveVoprf();

    assertThat(manager.performVerifiableHash("input-alpha", SERVER_ID).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
  }

  /**
   * A tampered element is what verification exists to catch. Without the proof the client would
   * unblind it into an output indistinguishable from a correct one.
   */
  @Test
  void performVerifiableHash_tamperedElement_throwsSecurityException() {
    when(accessor.handleVerifiableRequest(eq(SERVER_ID), any(VoprfRequest.class)))
        .thenAnswer(inv -> {
          VoprfResponse honest = new VoprfResponse(
              voprfServer.process(inv.getArgument(1, VoprfRequest.class).blindedRequest()));
          List<String> tampered = new ArrayList<>(honest.evaluatedElements());
          // Re-evaluate a different input under the same key: a valid point, honestly produced,
          // simply not the answer to what was asked.
          tampered.set(0, otherHonestElement());
          return new VoprfResponse(tampered, honest.proof(), honest.processIdentifier());
        });

    assertThatThrownBy(() -> manager.performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(SecurityException.class);
  }

  private String otherHonestElement() {
    VoprfClientManager other = new VoprfClientManager(voprfSuite, voprfDetail.publicKey());
    try (var ctx = other.hashingContext(List.of(INPUT_B))) {
      return voprfServer.process(other.eliminationRequest(ctx)).evaluatedPoints().get(0);
    }
  }

  @Test
  void performVerifiableHash_tamperedProof_throwsSecurityException() {
    when(accessor.handleVerifiableRequest(eq(SERVER_ID), any(VoprfRequest.class)))
        .thenAnswer(inv -> {
          VoprfResponse honest = new VoprfResponse(
              voprfServer.process(inv.getArgument(1, VoprfRequest.class).blindedRequest()));
          byte[] proof = Hex.decode(honest.proof());
          proof[0] ^= 0x01;
          return new VoprfResponse(honest.evaluatedElements(), Hex.toHexString(proof),
              honest.processIdentifier());
        });

    assertThatThrownBy(() -> manager.performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * A server evaluating with a key other than the one the client pinned is exactly the RFC 9497
   * §7.3 substitution the pin exists to detect.
   */
  @Test
  void performVerifiableHash_impostorServer_throwsSecurityException() {
    VerifiableProcessorDetail impostorDetail = VerifiableProcessorDetail.derive(
        voprfSuite, new BigInteger("99999999999999999999", 16), "proc-voprf");
    VoprfServerManager impostor = new VoprfServerManager(voprfSuite, () -> impostorDetail);
    when(accessor.handleVerifiableRequest(eq(SERVER_ID), any(VoprfRequest.class)))
        .thenAnswer(inv -> new VoprfResponse(
            impostor.process(inv.getArgument(1, VoprfRequest.class).blindedRequest())));

    assertThatThrownBy(() -> manager.performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(SecurityException.class);
  }

  // ─── POPRF ─────────────────────────────────────────────────────────────────

  @Test
  void performPartiallyObliviousHash_roundTripsAndVerifies() {
    servePoprf();

    HofmannHashResult result = manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("proc-poprf");
  }

  /**
   * The whole point of the public input: the same private input under a different {@code info} is
   * an unrelated output, not a related one.
   */
  @Test
  void performPartiallyObliviousHash_differentInfo_givesUnrelatedOutput() {
    servePoprf();

    byte[] one = manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash();
    byte[] two = manager.performPartiallyObliviousHash(
        INPUT_A, "tenant-b".getBytes(StandardCharsets.UTF_8), SERVER_ID).hash();

    assertThat(one).isNotEqualTo(two);
  }

  /**
   * Empty is a real public input, not the absence of one, and must produce a different output from
   * any non-empty value. RFC 9497's POPRF Finalize emits the length prefix even when empty, which
   * is what makes that true.
   */
  @Test
  void performPartiallyObliviousHash_emptyInfo_isAValidAndDistinctPublicInput() {
    servePoprf();

    byte[] empty = manager.performPartiallyObliviousHash(INPUT_A, new byte[0], SERVER_ID).hash();
    byte[] nonEmpty = manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash();

    assertThat(empty).isNotEmpty().isNotEqualTo(nonEmpty);
  }

  @Test
  void performPartiallyObliviousHash_nullInfo_isRejectedRatherThanDefaulted() {
    assertThatThrownBy(() ->
        manager.performPartiallyObliviousHash(INPUT_A, (byte[]) null, SERVER_ID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("different public inputs");
  }

  @Test
  void performPartiallyObliviousHash_batch_returnsOneResultPerInputInOrder() {
    servePoprf();

    List<HofmannHashResult> batch =
        manager.performPartiallyObliviousHash(List.of(INPUT_A, INPUT_B), INFO, SERVER_ID);

    assertThat(batch).hasSize(2);
    assertThat(batch.get(0).hash())
        .isEqualTo(manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash());
    assertThat(batch.get(1).hash())
        .isEqualTo(manager.performPartiallyObliviousHash(INPUT_B, INFO, SERVER_ID).hash());
  }

  /**
   * The proof is graded against the tweaked key the client derives from the {@code info} it asked
   * for. A response computed under a different public input therefore fails, which is what binds
   * the answer to the question.
   */
  @Test
  void performPartiallyObliviousHash_responseUnderADifferentInfo_throwsSecurityException() {
    when(accessor.handlePartiallyObliviousRequest(eq(SERVER_ID), any(PoprfRequest.class)))
        .thenAnswer(inv -> {
          PoprfRequest asked = inv.getArgument(1, PoprfRequest.class);
          PoprfRequest substituted = new PoprfRequest(
              asked.blindedElements(), Hex.toHexString("other-tenant".getBytes(StandardCharsets.UTF_8)),
              asked.requestId());
          return new PoprfResponse(poprfServer.process(substituted.blindedRequest()));
        });

    assertThatThrownBy(() -> manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID))
        .isInstanceOf(SecurityException.class);
  }

  // ─── Pinning is required ───────────────────────────────────────────────────

  @Test
  void verifiableModes_withoutAPinnedKey_refuseWithAnExplanation() {
    HofmannOprfClientManager unpinned = new HofmannOprfClientManager(accessor, Map.of());

    assertThatThrownBy(() -> unpinned.performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("authenticated out of band")
        .hasMessageContaining("withVoprfServerPublicKey");
    assertThatThrownBy(() -> unpinned.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("withPoprfServerPublicKey");
  }

  /**
   * A config that pins one mode does not silently enable the other.
   */
  @Test
  void pinningOneMode_doesNotEnableTheOther() {
    OprfClientConfig cfg = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build())
        .withVoprfServerPublicKey(Hex.toHexString(voprfDetail.publicKey()));
    HofmannOprfClientManager partial =
        new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, cfg));

    assertThatThrownBy(() -> partial.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("POPRF");
  }

  /**
   * The pinned key is cross-checked against what the server advertises before any request is sent,
   * so a rotated key fails saying so rather than as an unexplained run of proof failures.
   */
  @Test
  void pinnedKeyDisagreeingWithTheAdvertisedOne_failsBeforeAnyEvaluation() {
    OprfClientConfig cfg = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build())
        .withVoprfServerPublicKey(Hex.toHexString(voprfDetail.publicKey()));
    when(accessor.getOprfConfig(SERVER_ID)).thenReturn(
        new OprfClientConfigResponse("P256_SHA256", List.of(
            new com.codeheadsystems.hofmann.model.oprf.OprfModeInfo(
                "VOPRF", Hex.toHexString(poprfDetail.publicKey()), "proc-voprf", 64))));
    HofmannOprfClientManager pinned =
        new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, cfg));

    assertThatThrownBy(() -> pinned.performVerifiableHash(INPUT_A, SERVER_ID))
        .hasMessageContaining("Refusing to proceed");
  }

  @Test
  void agreeingPinnedKey_proceedsToEvaluate() {
    OprfClientConfig cfg = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build())
        .withVoprfServerPublicKey(Hex.toHexString(voprfDetail.publicKey()));
    when(accessor.getOprfConfig(SERVER_ID)).thenReturn(
        new OprfClientConfigResponse("P256_SHA256", List.of(
            new com.codeheadsystems.hofmann.model.oprf.OprfModeInfo(
                "VOPRF", Hex.toHexString(voprfDetail.publicKey()), "proc-voprf", 64))));
    serveVoprf();
    HofmannOprfClientManager pinned =
        new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, cfg));

    assertThat(pinned.performVerifiableHash(INPUT_A, SERVER_ID).hash()).isNotEmpty();
  }

  // ─── Batch bounds ──────────────────────────────────────────────────────────

  @Test
  void emptyBatch_isRejectedLocally() {
    assertThatThrownBy(() -> manager.performVerifiableHash(List.of(), SERVER_ID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("At least one input");
  }

  @Test
  void batchOverTheAbsoluteMaximum_isRejectedLocallyRatherThanOverTheWire() {
    List<byte[]> huge = new ArrayList<>();
    for (int i = 0; i < VoprfServerManager.ABSOLUTE_MAX_BATCH_SIZE + 1; i++) {
      huge.add(INPUT_A);
    }

    assertThatThrownBy(() -> manager.performVerifiableHash(huge, SERVER_ID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("absolute maximum");
  }
}
