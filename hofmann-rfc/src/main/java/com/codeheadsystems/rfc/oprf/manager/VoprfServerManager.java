package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.VerifiableBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProof;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProver;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RFC 9497 §3.3.2 VOPRF server: evaluates blinded elements and proves it used its committed key.
 */
public class VoprfServerManager {

  private static final Logger log = LoggerFactory.getLogger(VoprfServerManager.class);

  /**
   * Default cap on how many elements one request may carry.
   * <p>
   * Not a cryptographic bound — batch proofs are sound at any size, and the encoding permits tens
   * of thousands. It is a resource bound: each element costs the server a scalar multiplication on
   * the ladder plus its share of the proof, and the client chooses the count. The limit belongs
   * here rather than in the proof layer because the right value is a function of request size and
   * tail latency, which only the deployment knows.
   */
  public static final int DEFAULT_MAX_BATCH_SIZE = 64;

  /** Ceiling on the configurable cap. */
  public static final int ABSOLUTE_MAX_BATCH_SIZE = 1024;

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;
  private final Supplier<VerifiableProcessorDetail> supplier;
  private final int maxBatchSize;

  private final VerifiableServerSupport support;

  /**
   * Instantiates a new VOPRF server manager with the default batch cap.
   *
   * @param suite    the cipher suite, which must be in VOPRF mode
   * @param supplier supplies key material, re-read per request to support rotation
   */
  public VoprfServerManager(final OprfCipherSuite suite,
                            final Supplier<VerifiableProcessorDetail> supplier) {
    this(suite, supplier, DEFAULT_MAX_BATCH_SIZE);
  }

  /**
   * Instantiates a new VOPRF server manager.
   *
   * @param suite        the cipher suite, which must be in VOPRF mode
   * @param supplier     supplies key material, re-read per request to support rotation
   * @param maxBatchSize the largest batch this server will accept
   */
  public VoprfServerManager(final OprfCipherSuite suite,
                            final Supplier<VerifiableProcessorDetail> supplier,
                            final int maxBatchSize) {
    suite.assertMode(OprfMode.VOPRF);
    if (supplier == null) {
      throw new IllegalArgumentException("Key supplier is required");
    }
    if (maxBatchSize < 1 || maxBatchSize > ABSOLUTE_MAX_BATCH_SIZE) {
      throw new IllegalArgumentException(
          "Max batch size must be between 1 and " + ABSOLUTE_MAX_BATCH_SIZE);
    }
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
    this.supplier = supplier;
    this.maxBatchSize = maxBatchSize;
    this.support = new VerifiableServerSupport(suite, OprfMode.VOPRF);
    log.info("VoprfServerManager({}, maxBatch={})", suite.identifier(), maxBatchSize);
  }

  /**
   * Evaluates every blinded element in the request and returns them with one proof covering the
   * batch.
   *
   * @param request the client request
   * @return the evaluated elements and the proof
   */
  public VerifiableEvaluatedResponse process(final VerifiableBlindedRequest request) {
    List<String> points = request.blindedPoints();
    if (points.size() > maxBatchSize) {
      throw new IllegalArgumentException(
          "Batch of " + points.size() + " exceeds the configured maximum of " + maxBatchSize);
    }

    // Snapshot once for the whole batch. The supplier is a rotation seam, so re-reading it per
    // element could straddle a key swap and yield a batch evaluated under two keys — for which no
    // single proof exists, so the response would verify against neither.
    final VerifiableProcessorDetail detail = support.requireValidDetail(supplier.get());

    byte[][] blindedElements = new byte[points.size()][];
    byte[][] evaluatedElements = new byte[points.size()][];
    for (int i = 0; i < points.size(); i++) {
      byte[] blinded = VerifiableServerSupport.decode(
          points.get(i), "Blinded element " + i);
      // Rejects the identity, off-curve points, and non-compressed encodings. The last matters
      // beyond hygiene here: the proof transcript hashes these exact bytes, so evaluating a
      // re-encoded element would produce a proof the client cannot verify against what it sent.
      groupSpec.validateElement(blinded);
      blindedElements[i] = blinded;
      evaluatedElements[i] = groupSpec.scalarMultiply(detail.masterKey(), blinded);
    }

    DleqProof proof = DleqProver.generateProof(
        suite, detail.masterKey(), detail.publicKey(), blindedElements, evaluatedElements);

    List<String> evaluated = new ArrayList<>(evaluatedElements.length);
    for (byte[] element : evaluatedElements) {
      evaluated.add(Hex.toHexString(element));
    }
    return new VerifiableEvaluatedResponse(
        evaluated, Hex.toHexString(proof.serialize(suite)), detail.processorIdentifier());
  }

}
