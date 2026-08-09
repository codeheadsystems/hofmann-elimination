package com.codeheadsystems.rfc.opaque.model;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.util.Arrays;

/**
 * Result of a successful client-side authentication: { ke3, sessionKey, exportKey }.
 *
 * <p>Implements {@link AutoCloseable} so a caller that does not need the key material can clear
 * it rather than drop it. Both arrays are secrets and both were being abandoned: this library's
 * own client takes {@code ke3} out of here to send to the server and lets the rest fall out of
 * scope, so a full authentication left a live session key and a live export key on the heap
 * every time.
 *
 * <p>The export key is the one that matters. It is derived from {@code randomizedPwd} and is a
 * long-term client secret — the same value the registration flow now destroys when it drops it,
 * so leaving it here was the same defect on the other side of the protocol.
 *
 * <p><strong>Unlike {@link ClientAuthState} this does not copy on construction</strong>: the arrays
 * are freshly derived by {@code generateKE3} and have no other owner, so there is nothing to
 * decouple. Closing therefore clears the arrays a caller may still be holding a reference to.
 * Take what you need before closing.
 *
 * <p><strong>The guard on this type is weaker than on the others, and the difference is worth
 * knowing.</strong> {@link #sessionKey()} and {@link #exportKey()} throw
 * {@link ClosedContextException} after {@link #close()}, which stops a caller from reading back an
 * all-zero long-term secret and using it as a key. But this is a terminal output rather than
 * protocol state consumed by a later step, so there is no downstream exchange for
 * "fail at first touch" to protect. And the guard cannot address the trap that follows from the
 * paragraph above: a caller who reads {@code exportKey()} <em>before</em> closing keeps a live
 * reference that {@code close()} then zeroes under them, silently. That is inherent to a type
 * whose whole contract is "closing clears the arrays you are holding", and documentation is the
 * only fix for it. Copying on read was considered and rejected — it would mint a fresh unerasable
 * copy of a long-term secret on every access, which is the argument
 * {@code ClientHashingContext.input()} already makes for aliasing, and it would invert the
 * contract by leaving a reader holding live key material while believing they had destroyed it.
 *
 * <p><strong>A final class rather than a record</strong>, because refusing use-after-close needs a
 * mutable {@code closed} flag. See {@link ClientAuthState}.
 */
public final class AuthResult implements AutoCloseable {

  private final KE3 ke3;
  // final for the JMM final-field freeze — see ClientHashingContext.
  private final byte[] sessionKey;
  private final byte[] exportKey;

  private volatile boolean closed;

  /**
   * Instantiates a new auth result. The arrays are retained, not copied — see the class comment.
   *
   * @param ke3        the client's final AKE message
   * @param sessionKey the session key
   * @param exportKey  the export key
   */
  public AuthResult(final KE3 ke3, final byte[] sessionKey, final byte[] exportKey) {
    this.ke3 = ke3;
    this.sessionKey = sessionKey;
    this.exportKey = exportKey;
  }

  /**
   * Returns the client's final AKE message.
   *
   * <p><strong>Not guarded</strong>, unlike the two key accessors and unlike every accessor on the
   * client state types. {@code close()} does not zero {@code ke3} — it is a MAC over a public
   * transcript, and by the time anyone could read it back it has already been transmitted — so a
   * post-close read returns the same correct value it always did. Refusing it would remove the one
   * legitimate use-after-close on this type and protect nothing.
   *
   * @return the KE3
   */
  public KE3 ke3() {
    return ke3;
  }

  /**
   * Returns the session key, live and shared.
   *
   * @return the session key
   * @throws ClosedContextException if this result has been closed
   */
  public byte[] sessionKey() {
    assertOpen();
    return sessionKey;
  }

  /**
   * Returns the export key, live and shared.
   *
   * @return the export key
   * @throws ClosedContextException if this result has been closed
   */
  public byte[] exportKey() {
    assertOpen();
    return exportKey;
  }

  /**
   * Whether this result has been closed. A lifetime assertion, not a concurrency check.
   *
   * @return true if {@link #close()} has been called
   */
  public boolean isClosed() {
    return closed;
  }

  /**
   * Zeroes the session key and the export key, and refuses to hand either out again.
   */
  @Override
  public void close() {
    closed = true;
    Arrays.fill(sessionKey, (byte) 0);
    Arrays.fill(exportKey, (byte) 0);
  }

  private void assertOpen() {
    if (closed) {
      throw new ClosedContextException(
          "AuthResult has been closed and its session and export keys zeroed; "
              + "take what you need from it before closing");
    }
  }

  /**
   * Redacts both keys.
   *
   * <p>The record-generated {@code toString} disclosed nothing in decimal — there is no
   * {@link java.math.BigInteger} here and {@code byte[]} renders as an identity hash — so this is
   * not the fix that {@link ClientAuthState#toString()} is. It is written explicitly so that
   * adding a field later cannot open one silently.
   *
   * <p>Not guarded — see {@link ClientAuthState#toString()}.
   */
  @Override
  public String toString() {
    return "AuthResult[ke3=" + (ke3 == null ? "null" : "present")
        + ", sessionKey=<redacted>, exportKey=<redacted>, closed=" + closed + "]";
  }
}
