package com.codeheadsystems.rfc.common;

/**
 * Raised when a closed client context or client state is used again.
 *
 * <p>Every {@link AutoCloseable} in this library holds a copy of a caller secret and zeroes it on
 * {@code close()}. Before this type existed those objects had no idea they had been closed, so a
 * use-after-close read a run of zeroes and produced a well-formed answer derived from the wrong
 * input — no exception, nothing downstream the wiser. The verifiable OPRF modes hid it best: the
 * blinded elements are stored rather than recomputed, so the server evaluated correctly and its
 * DLEQ proof <em>verified</em>, leaving a wrong hash as the only symptom. OPAQUE registration was
 * the one case that reported nothing at all: it has no envelope MAC to fail against, so a closed
 * state produced a complete registration record keyed to a value no client can ever reproduce.
 * See {@code ClientRegistrationState.close()} for why that is a lockout rather than the
 * authentication bypass it first looks like.
 *
 * <p><strong>A subclass of {@link IllegalStateException} rather than the bare type, on purpose.</strong>
 * Use-after-close is an {@code IllegalStateException} by every Java convention, but BouncyCastle's
 * {@code DecoderException} also extends {@code IllegalStateException}, and this library's uniform
 * failure discipline exists precisely because of that — {@code OprfClientManager.hashResult} and
 * both verifiable managers' {@code decode} wrap it into a {@link SecurityException} so a hostile
 * server cannot choose which exception type the application sees. A caller who wants to
 * distinguish "I used a closed context" from "the peer sent malformed hex" must not be forced into
 * a {@code catch (IllegalStateException)} that catches both. Catching the supertype still works
 * for anyone who does not care.
 *
 * <p><strong>Not a {@link SecurityException}.</strong> That is reserved here for "the peer
 * misbehaved" — a failed DLEQ proof, a failed envelope MAC, malformed wire data. This is a
 * lifetime bug in the calling application, and filing it under the same type an application
 * catches to mean "the server is hostile" would misdirect the person reading the stack trace.
 *
 * <p><strong>It carries no secret and reveals nothing to a remote party.</strong> The condition is
 * purely local — the lifetime of the caller's own object — and is never a function of a
 * server-supplied value, so no peer can induce it or observe it. That is a property of <em>where
 * the guard sits</em>: in the accessors, upstream of anything the peer controls. Moving a check
 * downstream of a server-supplied value would make the failure server-observable in timing and
 * give away the property for free.
 */
public final class ClosedContextException extends IllegalStateException {

  /**
   * Instantiates a new closed context exception.
   *
   * @param message names the type that was closed and what to do about it; never a field value
   */
  public ClosedContextException(final String message) {
    super(message);
  }
}
