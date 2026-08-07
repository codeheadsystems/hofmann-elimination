package com.codeheadsystems.rfc.oprf.model;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Client-side state for one verifiable OPRF exchange, spanning one or more inputs.
 * <p>
 * Unlike {@link ClientHashingContext}, this retains the blinded elements. RFC 9497 §3.3.2
 * {@code Finalize} needs them: the proof is verified over the pair of element lists, so a client
 * that kept only its blinds could unblind but could not check the server's work — which is the
 * entire difference between this mode and the base one.
 * <p>
 * The three lists are positionally aligned and must stay that way. Entry {@code i} of each belongs
 * to the same input, and the evaluated elements the server returns are matched to them by index.
 * Losing that alignment does not fail loudly; it produces plausible-looking output derived from
 * the wrong pairing.
 *
 * @param requestId       correlates the request with its response
 * @param inputs          the client inputs, in order
 * @param blinds          the blinding scalars, aligned with {@code inputs}
 * @param blindedElements the serialized blinded elements, aligned with {@code inputs}
 */
public record VoprfClientContext(String requestId,
                                 List<byte[]> inputs,
                                 List<BigInteger> blinds,
                                 List<byte[]> blindedElements) {

  /**
   * Rejects a context whose lists are not aligned.
   */
  public VoprfClientContext {
    if (inputs == null || blinds == null || blindedElements == null) {
      throw new IllegalArgumentException("Context lists are required");
    }
    if (inputs.isEmpty()) {
      throw new IllegalArgumentException("Context must hold at least one input");
    }
    if (inputs.size() != blinds.size() || inputs.size() != blindedElements.size()) {
      throw new IllegalArgumentException(
          "Context lists must be the same length: inputs=" + inputs.size()
              + " blinds=" + blinds.size() + " blindedElements=" + blindedElements.size());
    }
    // Copy the arrays, not just the lists — List.copyOf makes the list immutable but leaves every
    // byte[] element aliased to the caller's. Matches PoprfClientContext, which has the sharper
    // version of the same problem in its tweakedKey; keeping the two consistent means neither
    // grows a divergent copying rule later. blinds needs no element copy: BigInteger is immutable.
    inputs = copyEach(inputs);
    blinds = List.copyOf(blinds);
    blindedElements = copyEach(blindedElements);
  }

  /**
   * Copies each element, rejecting nulls.
   *
   * <p>The explicit null rejection restores what {@code List.copyOf} was doing before this method
   * replaced it: {@code Stream.toList()} permits nulls where {@code List.copyOf} throws, so a
   * tolerant copy would have quietly turned a construction-time rejection into a stored null. That
   * null then surfaces much later — as {@code Hex.toHexString(null)}, or as an NPE inside
   * {@code DleqVerifier.verifyProof}, which catches {@code SecurityException} and
   * {@code IllegalArgumentException} but not NPE, so it would escape the uniform-failure
   * discipline that class documents. {@code blinds} still goes through {@code List.copyOf} and so
   * still rejects nulls; one constructor with two null contracts is worse than either contract.
   */
  private static List<byte[]> copyEach(final List<byte[]> values) {
    return values.stream()
        .map(v -> Objects.requireNonNull(v, "Context lists must not contain null elements").clone())
        .toList();
  }

  /**
   * Returns the client inputs, each element copied.
   *
   * @return the inputs
   */
  @Override
  public List<byte[]> inputs() {
    return copyEach(inputs);
  }

  /**
   * Returns the serialized blinded elements, each element copied.
   *
   * @return the blinded elements
   */
  @Override
  public List<byte[]> blindedElements() {
    return copyEach(blindedElements);
  }

  /**
   * Batch size.
   *
   * @return the number of inputs in this context
   */
  public int size() {
    return inputs.size();
  }

  /**
   * Redacts the blinds and the inputs.
   *
   * <p>{@code List.toString()} calls {@code BigInteger.toString()} on every element, so the
   * generated {@code toString} would print <em>every blind in the batch</em> in full decimal —
   * the same disclosure as {@link ClientHashingContext#blindingFactor()}, multiplied by batch
   * size. A blind lets an observer unblind the corresponding evaluated element and recover the
   * OPRF output for that input. The {@code List<byte[]>} fields are harmless on their own (each
   * element renders as an identity hash) but {@code inputs} is the client's plaintext, so it is
   * redacted too. Blinded elements are public and are left as a count.
   */
  @Override
  public String toString() {
    return "VoprfClientContext[requestId=" + requestId
        + ", inputs=<redacted>, blinds=<redacted>, blindedElements=" + blindedElements.size()
        + " element(s)]";
  }
}
