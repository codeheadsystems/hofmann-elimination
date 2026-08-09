package com.codeheadsystems.rfc.oprf.model;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import java.util.Arrays;
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
 * <p>
 * <strong>A closed context refuses to be used</strong> — every accessor that returns protocol
 * state throws {@link ClosedContextException}. See {@link #close()}.
 * <p>
 * <strong>A final class rather than a record</strong>, because refusing use-after-close needs a
 * mutable {@code closed} flag. See {@link ClientHashingContext} for the full argument.
 */
public final class PoprfClientContext implements AutoCloseable {

  private final String requestId;
  // final for the JMM final-field freeze — see ClientHashingContext.
  private final List<byte[]> inputs;
  private final List<BigInteger> blinds;
  private final List<byte[]> blindedElements;
  private final byte[] info;
  private final byte[] tweakedKey;

  private volatile boolean closed;

  /**
   * Rejects a context whose lists are not aligned or which is missing its POPRF-specific state,
   * and copies every array.
   *
   * @param requestId       correlates the request with its response
   * @param inputs          the client inputs, in order
   * @param blinds          the blinding scalars, aligned with {@code inputs}
   * @param blindedElements the serialized blinded elements, aligned with {@code inputs}
   * @param info            the public input, shared with the server and covered by the output
   * @param tweakedKey      the client-derived key the proof is graded against
   */
  public PoprfClientContext(final String requestId,
                            final List<byte[]> inputs,
                            final List<BigInteger> blinds,
                            final List<byte[]> blindedElements,
                            final byte[] info,
                            final byte[] tweakedKey) {
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
    this.requestId = requestId;
    this.inputs = copyEach(inputs);
    this.blinds = List.copyOf(blinds);
    this.blindedElements = copyEach(blindedElements);
    this.info = info.clone();
    this.tweakedKey = tweakedKey.clone();
  }

  /**
   * Zeroes this context's copies of the inputs and refuses all further use. See
   * {@link VoprfClientContext#close()}; the reasoning is identical, including the part where the
   * DLEQ proof still verified before the guard existed, and the two are kept in step deliberately.
   *
   * <p>Not {@code info} or {@code tweakedKey}: the public input is public by construction — it is
   * agreed with the server and covered by the output — and the tweaked key is derived from it and
   * the server's public key. Of the five components other than {@code requestId}, {@code inputs}
   * is the only secret one, and zeroing any of the rest would only make a reader wonder which.
   *
   * <p><strong>Zeroing {@code tweakedKey} would be actively wrong, not merely pointless.</strong>
   * An all-zero array is the ristretto255 encoding of the identity element, and {@code tweakedKey}
   * is the statement {@code hashResults} grades the server's DLEQ proof against. So it is
   * <em>guarded</em> instead: {@link #tweakedKey()} on a closed context throws rather than handing
   * back a key that is not the one the proof should be checked under. That is the one accessor
   * here whose guard has cryptographic content rather than lifetime-hygiene content.
   */
  @Override
  public void close() {
    closed = true;
    for (byte[] input : inputs) {
      Arrays.fill(input, (byte) 0);
    }
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
   * Returns the request identifier. Not guarded — see {@link ClientHashingContext#requestId()}.
   *
   * @return the request id
   */
  public String requestId() {
    return requestId;
  }

  /**
   * Returns a copy of the public input.
   *
   * <p>Guarded despite being public data, because this is one of the accessors
   * {@code eliminationRequest} reads — see {@link VoprfClientContext#close()} for why the
   * request-building accessors are the ones that make the guard work at all.
   *
   * @return a copy of the public input
   * @throws ClosedContextException if this context has been closed
   */
  public byte[] info() {
    assertOpen();
    return info.clone();
  }

  /**
   * Returns a copy of the client-derived tweaked key.
   *
   * @return a copy of the tweaked key
   * @throws ClosedContextException if this context has been closed
   */
  public byte[] tweakedKey() {
    assertOpen();
    return tweakedKey.clone();
  }

  /**
   * Returns the client inputs, each element copied.
   *
   * @return the inputs
   * @throws ClosedContextException if this context has been closed
   */
  public List<byte[]> inputs() {
    assertOpen();
    return copyEach(inputs);
  }

  /**
   * Returns the blinding scalars.
   *
   * @return the blinds
   * @throws ClosedContextException if this context has been closed
   */
  public List<BigInteger> blinds() {
    assertOpen();
    return blinds;
  }

  /**
   * Returns the serialized blinded elements, each element copied.
   *
   * @return the blinded elements
   * @throws ClosedContextException if this context has been closed
   */
  public List<byte[]> blindedElements() {
    assertOpen();
    return copyEach(blindedElements);
  }

  /**
   * Batch size. Not guarded — a count, carrying no secret, and useful when logging.
   *
   * @return the number of inputs in this context
   */
  public int size() {
    return inputs.size();
  }

  /**
   * Whether this context has been closed. A lifetime assertion, not a concurrency check — see
   * {@link ClientHashingContext#isClosed()}.
   *
   * @return true if {@link #close()} has been called
   */
  public boolean isClosed() {
    return closed;
  }

  private void assertOpen() {
    if (closed) {
      throw new ClosedContextException(
          "PoprfClientContext has been closed and its copies of the inputs zeroed; "
              + "scope the try-with-resources to the whole exchange");
    }
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
   *
   * <p>Not guarded — see {@link ClientHashingContext#toString()}.
   */
  @Override
  public String toString() {
    return "PoprfClientContext[requestId=" + requestId
        + ", inputs=<redacted>, blinds=<redacted>, blindedElements=" + blindedElements.size()
        + " element(s)"
        + ", info=<redacted>, tweakedKey=<redacted>, closed=" + closed
        + "]";
  }
}
