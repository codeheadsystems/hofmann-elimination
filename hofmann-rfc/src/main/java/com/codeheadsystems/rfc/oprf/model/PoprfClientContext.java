package com.codeheadsystems.rfc.oprf.model;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

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
    // Copy the arrays, not just the lists. List.copyOf makes the *list* immutable but leaves every
    // byte[] element aliased to the caller's, so a context could be mutated after construction
    // through a reference the caller still holds.
    //
    // tweakedKey is the one that has to be right: it is what DLEQ verification grades the server's
    // proof against, and it is the client's own m*G + pkS rather than anything the server sent.
    // Mutating it between construction and verification swaps the statement being proved — a proof
    // for a different public input would verify, which is exactly the binding this type exists to
    // enforce. info is copied for the same reason one step earlier: it is what tweakedKey is
    // derived from and what the output is bound to.
    //
    // blinds needs no element copy; BigInteger is immutable.
    inputs = copyEach(inputs);
    blinds = List.copyOf(blinds);
    blindedElements = copyEach(blindedElements);
    info = info.clone();
    tweakedKey = tweakedKey.clone();
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
   * Returns a copy of the public input.
   *
   * @return a copy of the public input
   */
  @Override
  public byte[] info() {
    return info.clone();
  }

  /**
   * Returns a copy of the client-derived tweaked key.
   *
   * @return a copy of the tweaked key
   */
  @Override
  public byte[] tweakedKey() {
    return tweakedKey.clone();
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
    return "PoprfClientContext[requestId=" + requestId
        + ", inputs=<redacted>, blinds=<redacted>, blindedElements=" + blindedElements.size()
        + " element(s)"
        + ", info=<redacted>, tweakedKey=<redacted>"
        + "]";
  }
}
