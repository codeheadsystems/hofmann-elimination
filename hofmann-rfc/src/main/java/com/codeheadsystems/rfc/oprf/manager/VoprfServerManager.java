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

  /**
   * The last key material whose public/secret correspondence was checked.
   * <p>
   * Consistency is verified when the key changes rather than on every request or never. Per
   * request would spend a fixed-base scalar multiplication detecting a static configuration error;
   * never would leave the one case startup validation structurally cannot see — a rotation
   * introducing a mismatched pair, which produces proofs that verify for no client, indefinitely,
   * and which reads as a client bug from the server side and as a compromise from the client side.
   * <p>
   * Racing threads may each validate the same new key once; that is harmless and cheaper than
   * synchronizing. Compared by value rather than by reference because a supplier is free to return
   * a fresh instance per call.
   */
  private volatile KeyIdentity lastValidated;

  /** The part of a detail that determines whether consistency needs rechecking. */
  private record KeyIdentity(String processorIdentifier, java.math.BigInteger masterKey) {
    static KeyIdentity of(VerifiableProcessorDetail detail) {
      return new KeyIdentity(detail.processorIdentifier(), detail.masterKey());
    }
  }

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
    final VerifiableProcessorDetail detail = supplier.get();
    validate(detail);

    byte[][] blindedElements = new byte[points.size()][];
    byte[][] evaluatedElements = new byte[points.size()][];
    for (int i = 0; i < points.size(); i++) {
      byte[] blinded = decode(points.get(i), i);
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

  /**
   * Decodes a hex field from the request.
   * <p>
   * BouncyCastle's {@code Hex.decode} throws {@code DecoderException}, which extends
   * {@link IllegalStateException} rather than {@link IllegalArgumentException}. Left unwrapped, a
   * client sending malformed hex would reach the HTTP adapters as a server error and become a 5xx
   * — letting any client manufacture 500s at will, and inverting blame in exactly the way the
   * comment on {@link #validate} takes pains to get right for the key case.
   */
  private static byte[] decode(final String hex, final int index) {
    try {
      return Hex.decode(hex);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(
          "Blinded element " + index + " is not valid hex", e);
    }
  }

  /**
   * Re-checks the supplied key material per request, because a rotating supplier can introduce a
   * key that startup validation never saw.
   * <p>
   * Rethrown as {@link IllegalStateException} deliberately. A bad key value is an
   * {@link IllegalArgumentException} at configuration time, but on this path it is a server
   * misconfiguration, and the HTTP adapters turn {@code IllegalArgumentException} into a 400 that
   * blames the caller. A key gone bad under rotation would then present as a healthy server
   * rejecting every client, which is precisely the failure this check exists to surface.
   */
  private void validate(final VerifiableProcessorDetail detail) {
    if (detail == null) {
      throw new IllegalStateException("Key supplier returned no VOPRF key material");
    }
    if (detail.mode() != OprfMode.VOPRF) {
      log.error("Key material for processor '{}' was derived for {} but is being used for VOPRF; "
              + "one secret must not serve two modes.",
          detail.processorIdentifier(), detail.mode());
      throw new IllegalStateException("VOPRF server key is configured for the wrong mode");
    }
    try {
      suite.validateSecretKey(detail.masterKey());
    } catch (IllegalArgumentException e) {
      log.error("VOPRF server key is unusable for processor '{}': {}. Every evaluation would "
              + "return the identity element.", detail.processorIdentifier(), e.getMessage());
      throw new IllegalStateException("VOPRF server key is misconfigured", e);
    }

    KeyIdentity identity = KeyIdentity.of(detail);
    if (!identity.equals(lastValidated)) {
      try {
        detail.validateConsistency(suite);
      } catch (IllegalArgumentException e) {
        log.error("VOPRF key material for processor '{}' is internally inconsistent: {}. "
                + "Proofs would be generated against a public key no client can match.",
            detail.processorIdentifier(), e.getMessage());
        throw new IllegalStateException("VOPRF server key pair is inconsistent", e);
      }
      lastValidated = identity;
    }
  }
}
