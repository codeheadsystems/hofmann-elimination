package com.codeheadsystems.rfc.opaque.model;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side state during authentication: { blind, password, ke1, clientAkePrivateKey }.
 *
 * <p><strong>The password is copied on construction, and {@link #close()} zeroes the copy.</strong>
 * That is what makes closing safe to do unconditionally. Holding the caller's array by reference
 * meant {@code close()} destroyed a buffer the caller still owned, and the library's own client
 * re-uses the password after authenticating — {@code authenticate()} passes it straight to
 * {@code changePassword} on key rotation. So the {@link AutoCloseable} could not actually be
 * invoked anywhere, and for the life of this type it never was: it was a mitigation that existed
 * but did not run. Copying decouples the two lifetimes, and the callers now close.
 *
 * <p>The cost is one extra copy of the password on the heap for the duration of the exchange.
 *
 * <p><strong>A closed state refuses to be used.</strong> Every accessor throws
 * {@link ClosedContextException}; see {@link #close()} for what used to happen instead.
 *
 * <p><strong>The caller still owns its own array.</strong> This zeroes what it copied, not what it
 * was given. A caller that wants its own buffer cleared must do that itself.
 *
 * <p><strong>Do not read this as "the password is then gone from memory". It is not.</strong>
 * {@code Arrays.fill} clears one copy of one buffer. A moving collector may already have copied
 * it, the page may already be in swap or a core dump, and the JLS does not forbid eliminating a
 * dead store. More concretely, this codebase makes copies that are not reachable to clear:
 * {@code SecretKeySpec} clones every HMAC key it is handed and its {@code destroy()} throws on the
 * default provider, and {@code hkdfExpand} leaves its last block in a local. Treat this as
 * shortening the window on one copy — defence in depth — not as a guarantee.
 *
 * <p><strong>{@code blind} is the bigger exposure here, and it cannot be cleared at all.</strong>
 * It is a {@link BigInteger}, and taken together with the {@code ke1} held in this same object it
 * is a password verifier: {@code blindedElement = blind · H(password)}, so anyone holding both
 * recovers {@code H(password)} as {@code blind⁻¹ · blindedElement} and can then run an offline
 * dictionary attack. Denying exactly that is what OPAQUE is for. An earlier version of this
 * comment called {@code blind} a password-independent per-exchange secret and the residue a
 * linkability concern; that was wrong, and a reviewer demonstrated password recovery from these
 * two fields alone. {@code clientAkePrivateKey} is the milder case the old text described.
 *
 * <p><strong>A final class rather than a record</strong>, because refusing use-after-close needs a
 * mutable {@code closed} flag. Making it one also forced {@link #toString()} to be written by
 * hand, which closed a disclosure that had been open the whole time — see there. The shape change
 * deliberately stops short of replacing {@code blind} and {@code clientAkePrivateKey} with a
 * zeroable scalar holder: that is the residual worth taking next, and this refactor is the one
 * that would make it cheap, but the two values are consumed as {@link BigInteger} by
 * {@code OpaqueAke.generateKE3} and {@code OpaqueCredentials} and changing that is a separate
 * piece of work.
 */
public final class ClientAuthState implements AutoCloseable {

  private final BigInteger blind;
  // final for the JMM final-field freeze; a record's components had it implicitly. See
  // ClientHashingContext for why a guard aimed at asynchronous misuse depends on it.
  private final byte[] password;
  private final KE1 ke1;
  private final BigInteger clientAkePrivateKey;

  private volatile boolean closed;

  /**
   * Copies the password so this object's lifetime is independent of the caller's array.
   *
   * @param blind               the OPRF blind
   * @param password            the password; copied, not retained
   * @param ke1                 the KE1 message
   * @param clientAkePrivateKey the client ephemeral AKE private key
   */
  public ClientAuthState(final BigInteger blind,
                         final byte[] password,
                         final KE1 ke1,
                         final BigInteger clientAkePrivateKey) {
    this.blind = blind;
    this.password = password.clone();
    this.ke1 = ke1;
    this.clientAkePrivateKey = clientAkePrivateKey;
  }

  /**
   * Returns the OPRF blind.
   *
   * @return the blind
   * @throws ClosedContextException if this state has been closed
   */
  public BigInteger blind() {
    assertOpen();
    return blind;
  }

  /**
   * Returns this state's copy of the password, live and shared.
   *
   * @return the password
   * @throws ClosedContextException if this state has been closed
   */
  public byte[] password() {
    assertOpen();
    return password;
  }

  /**
   * Returns the KE1 message.
   *
   * @return the KE1
   * @throws ClosedContextException if this state has been closed
   */
  public KE1 ke1() {
    assertOpen();
    return ke1;
  }

  /**
   * Returns the client ephemeral AKE private key.
   *
   * @return the client AKE private key
   * @throws ClosedContextException if this state has been closed
   */
  public BigInteger clientAkePrivateKey() {
    assertOpen();
    return clientAkePrivateKey;
  }

  /**
   * Whether this state has been closed. A lifetime assertion, not a concurrency check.
   *
   * @return true if {@link #close()} has been called
   */
  public boolean isClosed() {
    return closed;
  }

  /**
   * Zeroes this object's copy of the password and refuses all further use.
   *
   * <p><strong>Close after the exchange, never during one.</strong> {@code generateKE3} reads
   * {@code password} to re-derive the OPRF output, so before the guard existed a closed state
   * derived from a run of zeroes: {@code recoverCredentials} then failed its envelope MAC and
   * threw {@code SecurityException("Authentication failed")}, indistinguishable from a wrong
   * password. The user was told their password was wrong when the real fault was a lifetime bug in
   * the caller. Now the accessor throws {@link ClosedContextException} instead, and the two
   * failures are distinguishable.
   *
   * <p><strong>The guard fires early, and that is what keeps it free.</strong> It throws at
   * {@code generateKE3}'s first read of this state — before {@code recoverCredentials}, before the
   * KSF stretch, before any server-supplied value is consumed. So a remote party can neither
   * induce the condition nor observe it; the old behaviour actually leaked slightly more, since a
   * closed state ran a full authentication's worth of work before going silent. Any future check
   * of this kind belongs in the accessor for the same reason.
   *
   * <p>The flag is set before the zeroing; see {@link com.codeheadsystems.rfc.common.ClosedContextException}
   * and {@code ClientHashingContext.close()} for the race that ordering narrows but does not
   * remove.
   */
  @Override
  public void close() {
    closed = true;
    Arrays.fill(password, (byte) 0);
  }

  private void assertOpen() {
    if (closed) {
      throw new ClosedContextException(
          "ClientAuthState has been closed and its copy of the password zeroed; "
              + "scope the try-with-resources to the whole authentication");
    }
  }

  /**
   * Redacts both scalars and the password.
   *
   * <p>There was no {@code toString} here at all while this was a record, so the generated one
   * printed <strong>two</strong> {@link BigInteger}s in full decimal. {@code blind} is the serious
   * one: this class's own documentation explains that a blind plus the corresponding blinded
   * element recovers {@code H(password)} and admits an offline dictionary attack, and while the
   * generated {@code toString} did not itself print that element — {@code KE1} and
   * {@code CredentialRequest} have no {@code toString} of their own, so their arrays rendered as
   * identity hashes — the element is on the wire and in the server's hands, so a log holder
   * generally has the other half. {@code clientAkePrivateKey} is the second: it yields this
   * session's {@code dh1} and {@code dh2} directly.
   *
   * <p>The three OPRF client contexts have redacted their blinds for this reason since they were
   * written. The two OPAQUE states were simply missed.
   *
   * <p>Not guarded, so a debugger or log formatter cannot turn a lifetime bug into a second,
   * more confusing failure.
   */
  @Override
  public String toString() {
    return "ClientAuthState[blind=<redacted>, password=<redacted>, ke1=" + (ke1 == null ? "null" : "present")
        + ", clientAkePrivateKey=<redacted>, closed=" + closed + "]";
  }
}
