package com.codeheadsystems.rfc.oprf.model;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import java.util.Arrays;
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
 * <p>
 * <strong>A closed context refuses to be used</strong> — every accessor that returns protocol
 * state throws {@link ClosedContextException}. See {@link #close()}, which is where the reasoning
 * for this mode specifically lives; the verifiable modes are where use-after-close hid best.
 * <p>
 * <strong>A final class rather than a record</strong>, because refusing use-after-close needs a
 * mutable {@code closed} flag. See {@link ClientHashingContext} for the full argument, including
 * why value equality was not re-implemented.
 */
public final class VoprfClientContext implements AutoCloseable {

  private final String requestId;
  // final for the JMM final-field freeze, which a record gave for nothing and a hand-written class
  // has to ask for. See ClientHashingContext for why that matters to a guard whose stated purpose
  // is surviving an asynchronous round trip.
  private final List<byte[]> inputs;
  private final List<BigInteger> blinds;
  private final List<byte[]> blindedElements;

  private volatile boolean closed;

  /**
   * Rejects a context whose lists are not aligned, and copies every element.
   *
   * @param requestId       correlates the request with its response
   * @param inputs          the client inputs, in order
   * @param blinds          the blinding scalars, aligned with {@code inputs}
   * @param blindedElements the serialized blinded elements, aligned with {@code inputs}
   */
  public VoprfClientContext(final String requestId,
                            final List<byte[]> inputs,
                            final List<BigInteger> blinds,
                            final List<byte[]> blindedElements) {
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
    this.requestId = requestId;
    this.inputs = copyEach(inputs);
    this.blinds = List.copyOf(blinds);
    this.blindedElements = copyEach(blindedElements);
  }

  /**
   * Zeroes this context's copies of the inputs and refuses all further use.
   *
   * <p>The constructor copies every input so the context cannot be mutated through a reference the
   * caller kept; the consequence was a copy of the client's plaintext OPRF input that the caller
   * had no way to erase. This closes that, and pairs with {@link ClientHashingContext#close()} so
   * the property does not depend on which mode you picked.
   *
   * <p>Only the inputs are zeroed. {@code blindedElements} goes to the server, so it is not secret;
   * {@code blinds} are {@link BigInteger} and cannot be zeroed at the Java level, which matters —
   * a blind together with its blinded element still recovers the input's OPRF output, so closing
   * this shortens a window rather than emptying the context. Both are nevertheless <em>guarded</em>
   * against a closed read, for the reason below.
   *
   * <p>Anything handed out by {@link #inputs()} is the caller's own copy and is not touched here.
   *
   * <p><strong>Close after the exchange, never during one. This mode is where the guard earns its
   * keep, because this mode hid the mistake best.</strong> {@code eliminationRequest} returns the
   * blinded elements this context already holds rather than recomputing them — it never touches
   * the zeroed inputs at all. So before the guard existed, a closed context still produced a
   * request the server received correctly, evaluated correctly, and returned a proof for that
   * <em>verified</em>: the DLEQ check that exists to catch a misbehaving server said nothing,
   * because the server did not misbehave. Only {@code Finalize} read the zeroed inputs, so a wrong
   * hash was the single symptom, and it arrived a full round trip after the mistake.
   *
   * <p><strong>Which is why {@link #blindedElements()} is guarded and not just {@link #inputs()}.
   * </strong> Guarding only the field that gets zeroed would leave exactly that case intact and
   * merely move the failure to {@code hashResults}, after the request had already gone to the
   * server. A closed context is not a context missing one field; it is not a context.
   *
   * <p>See {@link ClientHashingContext#close()} for the flag-then-zero ordering and the
   * check-then-read race this does not remove.
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
   * <p>Guarded even though blinded elements are public by construction — they are what goes to the
   * server. The guard is here because this is the accessor {@code eliminationRequest} reads, and
   * it is therefore the one that decides whether a closed context fails before the network call or
   * a round trip after it. See {@link #close()}.
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
          "VoprfClientContext has been closed and its copies of the inputs zeroed; "
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
    return "VoprfClientContext[requestId=" + requestId
        + ", inputs=<redacted>, blinds=<redacted>, blindedElements=" + blindedElements.size()
        + " element(s), closed=" + closed + "]";
  }
}
