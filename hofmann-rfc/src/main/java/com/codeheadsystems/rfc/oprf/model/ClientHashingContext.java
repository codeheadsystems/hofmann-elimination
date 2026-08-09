package com.codeheadsystems.rfc.oprf.model;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side context for hashing: { requestId, blindingFactor, input }.
 *
 * <p><strong>The input is copied on construction, and {@link #close()} zeroes the copy.</strong>
 * Copying decouples this object's lifetime from the caller's array, so a caller who clears their
 * own buffer immediately after handing it over does not pull the value out from under an exchange
 * still in flight — and, conversely, closing this does not destroy a buffer the caller still owns.
 * The verifiable-mode contexts copy for the same reason; they gained {@code close()} alongside this
 * one so that "the library keeps an unclearable copy of your secret" stops being true of any of
 * the three.
 *
 * <p><strong>A closed context refuses to be used.</strong> Every accessor that returns protocol
 * state throws {@link ClosedContextException}; see {@link #close()} for what used to happen
 * instead and why {@link #requestId()} is exempt.
 *
 * <p><strong>Do not read this as "the input is then gone from memory".</strong> {@code Arrays.fill}
 * clears one copy of one buffer. A moving collector may already have copied it, the page may
 * already be in swap or a core dump, and the JLS does not forbid eliminating a dead store. Treat
 * it as shortening the window on one copy.
 *
 * <p><strong>{@code blindingFactor} cannot be cleared at all</strong>, and taken together with the
 * blinded element derived from this same context it is what lets an observer recover the OPRF
 * output for this input. It is a {@link BigInteger}; nothing at the Java level can zero it. The
 * same caveat, for the same reason, appears on OPAQUE's {@code ClientAuthState}.
 *
 * <p><strong>A final class rather than a record</strong>, because refusing use-after-close needs a
 * mutable {@code closed} flag and a record cannot carry one. The alternative considered and
 * rejected was sniffing the input for an all-zero run, which would refuse a legal OPRF input in
 * order to detect an illegal call. The visible consequences of not being a record are that
 * {@code equals}/{@code hashCode} are now identity-based and that record patterns no longer
 * deconstruct it. Value equality was not re-implemented on purpose: the generated one compared
 * {@code byte[]} by reference and was already near-useless here, and a content-based replacement
 * would be a variable-time comparison of secret material, which is a worse thing to hand a caller
 * than no {@code equals} at all.
 */
public final class ClientHashingContext implements AutoCloseable {

  private final String requestId;
  private final BigInteger blindingFactor;
  // final, and that is load-bearing rather than stylistic. A record's components are implicitly
  // final and so get the JMM final-field freeze: safe publication to another thread with no
  // synchronisation. Dropping to a hand-written class with non-final fields would quietly lose
  // that — and an asynchronous round trip, which is the very shape this guard exists for, is
  // cross-thread publication. Without final, a second thread could observe a half-built context
  // regardless of what the closed flag says.
  private final byte[] input;

  /**
   * Volatile so a close on one thread is visible to a guard check on another. That is all it does:
   * see {@link #close()} for the check-then-read race it does not remove.
   */
  private volatile boolean closed;

  /**
   * Copies the input so this object's lifetime is independent of the caller's array.
   *
   * @param requestId      correlates the request with its response
   * @param blindingFactor the blinding scalar
   * @param input          the client input; copied, not retained
   */
  public ClientHashingContext(final String requestId,
                              final BigInteger blindingFactor,
                              final byte[] input) {
    if (input == null) {
      throw new IllegalArgumentException("Input is required");
    }
    this.requestId = requestId;
    this.blindingFactor = blindingFactor;
    this.input = input.clone();
  }

  /**
   * Returns the request identifier.
   *
   * <p>Not guarded, along with {@link #toString()} and {@link #isClosed()}. It is correlation
   * metadata rather than protocol state — it carries no secret and nothing is computed from it —
   * and it is exactly what you want available when logging why a context was closed.
   *
   * @return the request id
   */
  public String requestId() {
    return requestId;
  }

  /**
   * Returns the blinding scalar.
   *
   * @return the blinding factor
   * @throws ClosedContextException if this context has been closed
   */
  public BigInteger blindingFactor() {
    assertOpen();
    return blindingFactor;
  }

  /**
   * Returns this context's input array directly, <strong>not</strong> a copy.
   *
   * <p>Deliberately unlike {@link VoprfClientContext#inputs()}, which copies on read, and the
   * asymmetry is worth a sentence rather than being left for someone to notice. Copying on read
   * would mint a fresh unerasable plaintext copy of the secret on every access — two per exchange
   * on the normal path, since {@code eliminationRequest} and {@code hashResult} each read it —
   * which cuts directly against the reason this class copies and clears at all. The verifiable
   * contexts pay that cost to protect a batch whose list alignment is load-bearing; there is no
   * alignment to protect here.
   *
   * <p>The price is that a caller can mutate this context through the returned array, and that
   * changing it mid-exchange produces a wrong answer rather than an error. The guard does not help
   * there — it refuses a closed context, not a mutated one.
   *
   * @return the input, live and shared with this context
   * @throws ClosedContextException if this context has been closed
   */
  public byte[] input() {
    assertOpen();
    return input;
  }

  /**
   * Whether this context has been closed.
   *
   * <p>A lifetime assertion for a caller holding a context across an asynchronous boundary who
   * would rather check than catch. <strong>It is not a concurrency check</strong>: a {@code false}
   * here is a statement about the past, not a reservation on the future, and a close on another
   * thread can land between this call and the accessor that follows it.
   *
   * @return true if {@link #close()} has been called
   */
  public boolean isClosed() {
    return closed;
  }

  /**
   * Zeroes this context's copy of the input and refuses all further use. Idempotent, and safe to
   * call from a {@code try}-with-resources around a whole exchange.
   *
   * <p>The caller still owns its own array; this clears what was copied, not what was given.
   *
   * <p><strong>Close this after the exchange, never during one.</strong> {@code eliminationRequest}
   * and {@code hashResult} both read {@code input}, so before the guard existed either call
   * against a closed context blinded or finalized over a run of zeroes and returned a well-formed
   * value derived from the wrong input, with no exception and nothing downstream the wiser. Now
   * they throw {@link ClosedContextException}. The scope rule has not changed — the
   * {@code try}-with-resources must still enclose the whole exchange — but breaking it is now
   * loud, which is what makes an asynchronous round trip a bug you find rather than a hash you
   * trust.
   *
   * <p><strong>The flag is set before the zeroing, and that ordering is deliberate</strong>: after
   * the volatile write no new reader gets past {@code assertOpen}. It narrows the race rather than
   * removing it. A reader already past the guard can still have the array zeroed under it, which
   * is inherent to clearing a buffer someone may be reading and is not fixable without a lock on
   * every read. The guard turns the realistic sequential misuse into an immediate failure; it is
   * not a concurrency control, and a context must not be shared across threads.
   */
  @Override
  public void close() {
    closed = true;
    Arrays.fill(input, (byte) 0);
  }

  private void assertOpen() {
    if (closed) {
      throw new ClosedContextException(
          "ClientHashingContext has been closed and its copy of the input zeroed; "
              + "scope the try-with-resources to the whole exchange");
    }
  }

  /**
   * Redacts the blinding factor and the input.
   *
   * <p>Same shape as {@link ServerProcessorDetail}: the generated {@code toString} would print
   * {@code blindingFactor} as its full decimal value. Disclosing a blind lets an observer unblind
   * the corresponding evaluated element and recover the OPRF output for that input — and on the
   * OPAQUE path that output is what the envelope keys derive from. {@code input} is redacted too
   * because it is the client's plaintext OPRF input.
   *
   * <p>Not guarded. A {@code toString} that throws turns a lifetime bug into a confusing secondary
   * failure inside a debugger or a log formatter, which is the worst place to discover one.
   */
  @Override
  public String toString() {
    return "ClientHashingContext[requestId=" + requestId
        + ", blindingFactor=<redacted>, input=<redacted>, closed=" + closed + "]";
  }
}
