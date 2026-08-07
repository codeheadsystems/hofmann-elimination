package com.codeheadsystems.hofmann.model.oprf;

/**
 * Request-size bounds for the verifiable OPRF endpoints, derived from the batch cap.
 *
 * <p>The verifiable servers already refuse a batch above their configured maximum — 64 by default,
 * 1024 absolute — and they do it before any curve operation, so the expensive work is bounded.
 * What that check cannot bound is the work done <em>before</em> it: by the time
 * {@code VoprfServerManager.process} sees a {@code List<String>}, the HTTP layer has read the whole
 * body and Jackson has materialised every element. A caller could send far more elements than the
 * cap allows and have all of them parsed and allocated before one is rejected.
 *
 * <p>The generic body limit (64 KiB by default) does bound that, but only loosely: at ~138 bytes
 * per hex-encoded P-521 element it admits roughly 470 elements against a cap of 64. Sizing the
 * limit from the cap itself closes the gap, and keeps the two in step if either is retuned.
 *
 * <p>This is a transport concern rather than a protocol one, which is why it lives with the wire
 * models and is applied by the adapters rather than inside the managers.
 */
public final class VerifiableOprfLimits {

  /**
   * Largest supported element, in bytes: a compressed SEC1 point on P-521.
   *
   * <p>Deliberately the maximum across suites rather than the configured suite's own size. The
   * bound is a coarse transport guard, and a per-suite value would make the limit change under a
   * suite switch for no benefit — the exact element size is enforced downstream by
   * {@code validateElement}, which is where a wrong-length element should be rejected and named.
   */
  public static final int MAX_ELEMENT_BYTES = 67;

  /**
   * Bytes allowed for everything that is not a batch element: the JSON envelope, the request id,
   * and — on POPRF — the public input. Generous, because {@code info} is application-defined.
   */
  public static final int ENVELOPE_ALLOWANCE_BYTES = 8192;

  private VerifiableOprfLimits() {
  }

  /**
   * Returns the maximum request body size for a verifiable endpoint at the given batch cap.
   *
   * <p>Each element costs two hex characters per byte plus JSON quoting and a separator, so four
   * characters of overhead. The envelope allowance covers the rest of the document.
   *
   * @param maxBatchSize the configured maximum batch size
   * @return the maximum request body size in bytes
   */
  public static long maxRequestBodyBytes(final int maxBatchSize) {
    if (maxBatchSize < 1) {
      throw new IllegalArgumentException("Max batch size must be at least 1");
    }
    return (long) maxBatchSize * (2L * MAX_ELEMENT_BYTES + 4L) + ENVELOPE_ALLOWANCE_BYTES;
  }
}
