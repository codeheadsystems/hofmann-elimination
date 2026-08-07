package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.PartiallyBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.PublicInput;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProof;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProver;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RFC 9497 §3.3.3 POPRF server: evaluates under a key tweaked by the public input.
 * <p>
 * Two things differ from VOPRF beyond the tweak itself, and both are easy to get wrong in ways
 * that still round-trip. The evaluation is an <em>inverse</em> multiplication,
 * {@code evaluatedElement = t^-1 * blindedElement} with {@code t = skS + m}, so the relation the
 * proof attests runs {@code blindedElement = t * evaluatedElement} — which is why the element
 * lists are passed to the prover in the opposite order from VOPRF. And the key the proof is made
 * against is {@code t * G}, recomputed for every request because it depends on {@code info}; the
 * cached {@code pkS} on the key material must never be used here.
 */
public class PoprfServerManager {

  private static final Logger log = LoggerFactory.getLogger(PoprfServerManager.class);

  /** Default cap on how many elements one request may carry. */
  public static final int DEFAULT_MAX_BATCH_SIZE = VoprfServerManager.DEFAULT_MAX_BATCH_SIZE;

  /** Ceiling on the configurable cap. */
  public static final int ABSOLUTE_MAX_BATCH_SIZE = VoprfServerManager.ABSOLUTE_MAX_BATCH_SIZE;

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;
  private final Supplier<VerifiableProcessorDetail> supplier;
  private final int maxBatchSize;
  private final VerifiableServerSupport support;

  /**
   * Instantiates a new POPRF server manager with the default batch cap.
   *
   * @param suite    the cipher suite, which must be in POPRF mode
   * @param supplier supplies key material, re-read per request to support rotation
   */
  public PoprfServerManager(final OprfCipherSuite suite,
                            final Supplier<VerifiableProcessorDetail> supplier) {
    this(suite, supplier, DEFAULT_MAX_BATCH_SIZE);
  }

  /**
   * Instantiates a new POPRF server manager.
   *
   * @param suite        the cipher suite, which must be in POPRF mode
   * @param supplier     supplies key material, re-read per request to support rotation
   * @param maxBatchSize the largest batch this server will accept
   */
  public PoprfServerManager(final OprfCipherSuite suite,
                            final Supplier<VerifiableProcessorDetail> supplier,
                            final int maxBatchSize) {
    suite.assertMode(OprfMode.POPRF);
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
    this.support = new VerifiableServerSupport(suite, OprfMode.POPRF);
    log.info("PoprfServerManager({}, maxBatch={})", suite.identifier(), maxBatchSize);
  }

  /**
   * Evaluates every blinded element under the request's public input and returns one proof
   * covering the batch.
   *
   * @param request the client request
   * @return the evaluated elements and the proof
   */
  public PartiallyEvaluatedResponse process(final PartiallyBlindedRequest request) {
    List<String> points = request.blindedPoints();
    if (points.size() > maxBatchSize) {
      throw new IllegalArgumentException(
          "Batch of " + points.size() + " exceeds the configured maximum of " + maxBatchSize);
    }
    byte[] info = VerifiableServerSupport.decode(request.info(), "Public input");
    PublicInput.validate(info);

    // Snapshot once for the whole batch, as in VOPRF: a proof is per-key, so a batch straddling a
    // rotation would verify against neither key.
    final VerifiableProcessorDetail detail = support.requireValidDetail(supplier.get());

    BigInteger t = tweakedKey(detail, info);
    BigInteger tInverse = suite.scalarInverse(t);

    byte[][] blindedElements = new byte[points.size()][];
    byte[][] evaluatedElements = new byte[points.size()][];
    for (int i = 0; i < points.size(); i++) {
      byte[] blinded = VerifiableServerSupport.decode(points.get(i), "Blinded element " + i);
      groupSpec.validateElement(blinded);
      blindedElements[i] = blinded;
      evaluatedElements[i] = groupSpec.scalarMultiply(tInverse, blinded);
    }

    // B is t*G, derived here rather than taken from detail.publicKey(): the key being proven
    // against depends on info and changes with every distinct public input.
    byte[] tweakedPublicKey = groupSpec.scalarMultiplyGenerator(t);

    // Element lists reversed relative to VOPRF, because blindedElement = t * evaluatedElement.
    DleqProof proof = DleqProver.generateProof(
        suite, t, tweakedPublicKey, evaluatedElements, blindedElements);

    List<String> evaluated = new ArrayList<>(evaluatedElements.length);
    for (byte[] element : evaluatedElements) {
      evaluated.add(Hex.toHexString(element));
    }
    return new PartiallyEvaluatedResponse(
        evaluated, Hex.toHexString(proof.serialize(suite)), detail.processorIdentifier());
  }

  /**
   * Computes {@code t = skS + m}, rejecting the degenerate case loudly.
   * <p>
   * RFC 9497 §3.3.3 raises {@code InverseError} when {@code t == 0}, and is explicit about what it
   * means: {@code t} is zero only when the client's public input hashes to the negation of the
   * server's secret key, so "clients that cause this error should be assumed to know the server
   * private key" and the server "should replace its private key". This is an intrusion signal, not
   * routine input validation, and it is logged as one.
   */
  private BigInteger tweakedKey(final VerifiableProcessorDetail detail, final byte[] info) {
    BigInteger n = groupSpec.groupOrder();
    BigInteger t = detail.masterKey().add(PublicInput.toScalar(suite, info)).mod(n);
    if (t.signum() == 0) {
      log.error("POPRF public input for processor '{}' tweaked the server key to zero. This "
              + "requires the public input to hash to the negation of the secret key, so the "
              + "client should be assumed to know that key. Replace it.",
          detail.processorIdentifier());
      throw new IllegalStateException(
          "POPRF tweaked key is zero; the server key should be considered compromised");
    }
    return t;
  }
}
