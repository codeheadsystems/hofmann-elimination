package com.codeheadsystems.rfc.oprf.model;

import java.math.BigInteger;
import java.util.List;

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
    inputs = List.copyOf(inputs);
    blinds = List.copyOf(blinds);
    blindedElements = List.copyOf(blindedElements);
  }

  /**
   * Batch size.
   *
   * @return the number of inputs in this context
   */
  public int size() {
    return inputs.size();
  }
}
