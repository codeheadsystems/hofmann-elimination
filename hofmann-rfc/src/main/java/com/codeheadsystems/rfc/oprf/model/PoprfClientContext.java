package com.codeheadsystems.rfc.oprf.model;

import java.math.BigInteger;
import java.util.List;

/**
 * Client-side state for one partially-oblivious exchange.
 * <p>
 * A distinct type from {@link VoprfClientContext} rather than one with nullable extras. POPRF
 * needs two things VOPRF does not — the public input, and the tweaked key derived from it — and a
 * single record with an "either a public key or a tweaked key" field is precisely where a POPRF
 * context ends up being graded against a raw {@code pkS}, which would accept a proof that says
 * nothing about the {@code info} the client asked for.
 * <p>
 * The {@code tweakedKey} is the client's <em>own</em> computation, {@code m * G + pkS}, never a
 * value taken from the server. That is what binds the proof to this particular {@code info}: a
 * server evaluating under a different public input produces a proof against a different tweaked
 * key, and verification fails.
 *
 * @param requestId       correlates the request with its response
 * @param inputs          the client inputs, in order
 * @param blinds          the blinding scalars, aligned with {@code inputs}
 * @param blindedElements the serialized blinded elements, aligned with {@code inputs}
 * @param info            the public input, shared with the server and covered by the output
 * @param tweakedKey      the client-derived key the proof is graded against
 */
public record PoprfClientContext(String requestId,
                                 List<byte[]> inputs,
                                 List<BigInteger> blinds,
                                 List<byte[]> blindedElements,
                                 byte[] info,
                                 byte[] tweakedKey) {

  /**
   * Rejects a context whose lists are not aligned or which is missing its POPRF-specific state.
   */
  public PoprfClientContext {
    if (inputs == null || blinds == null || blindedElements == null) {
      throw new IllegalArgumentException("Context lists are required");
    }
    if (info == null) {
      throw new IllegalArgumentException("Public input is required; use an empty array for none");
    }
    if (tweakedKey == null || tweakedKey.length == 0) {
      throw new IllegalArgumentException("Tweaked key is required");
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
    return "PoprfClientContext[requestId=" + requestId
        + ", inputs=<redacted>, blinds=<redacted>, blindedElements=" + blindedElements.size()
        + " element(s)"
        + ", info=<redacted>, tweakedKey=<redacted>"
        + "]";
  }
}
