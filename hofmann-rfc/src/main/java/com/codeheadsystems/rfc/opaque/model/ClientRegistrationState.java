package com.codeheadsystems.rfc.opaque.model;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side state during registration: { blind, password, request }.
 *
 * <p><strong>The password is copied on construction, and {@link #close()} zeroes the copy.</strong>
 * See {@link ClientAuthState} for why the previous by-reference behaviour made the
 * {@link AutoCloseable} unusable in practice, and therefore unused.
 *
 * <p><strong>A closed state refuses to be used.</strong> Every accessor throws
 * {@link ClosedContextException}. This is the type where that mattered most, and it was missed
 * when the hazard was first written down — see {@link #close()}.
 *
 * <p><strong>The caller still owns its own array.</strong> This zeroes what it copied, not what it
 * was given.
 *
 * <p><strong>{@code blind} cannot be zeroed, and it is a password verifier.</strong> It is a
 * {@link BigInteger}, and with the {@code request} held in this same object —
 * {@code blindedElement = blind · H(password)} — anyone holding both recovers {@code H(password)}
 * and can mount an offline dictionary attack without the server. That is a stronger statement
 * than the earlier one here, which said {@code blind} plus the evaluated element plus
 * <em>the password</em> reproduces {@code randomizedPwd}; the real attack needs no password at
 * all. See {@link ClientAuthState} for the same point and for why clearing the array is defence
 * in depth rather than a guarantee.
 *
 * <p><strong>A final class rather than a record</strong>, because refusing use-after-close needs a
 * mutable {@code closed} flag. See {@link ClientAuthState}.
 */
public final class ClientRegistrationState implements AutoCloseable {

  private final BigInteger blind;
  // final for the JMM final-field freeze — see ClientHashingContext.
  private final byte[] password;
  private final RegistrationRequest request;

  private volatile boolean closed;

  /**
   * Copies the password so this object's lifetime is independent of the caller's array.
   *
   * @param blind    the OPRF blind
   * @param password the password; copied, not retained
   * @param request  the registration request
   */
  public ClientRegistrationState(final BigInteger blind,
                                 final byte[] password,
                                 final RegistrationRequest request) {
    this.blind = blind;
    this.password = password.clone();
    this.request = request;
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
   * Returns the registration request.
   *
   * @return the request
   * @throws ClosedContextException if this state has been closed
   */
  public RegistrationRequest request() {
    assertOpen();
    return request;
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
   * <p><strong>This was the only instance of the use-after-close hazard that produced no error
   * anywhere, and it was not on the list when the hazard was first written down.</strong> The entry
   * named the two OPRF cases and {@code ClientAuthState}, where a closed state at least fails — the
   * envelope MAC does not verify and authentication is refused. Registration has no such check.
   * {@code OpaqueCredentials.finalizeRegistration} reads {@code password} and {@code blind} to
   * derive {@code randomizedPwd}, and nothing downstream rejects an all-zero OPRF input:
   * {@code OprfCipherSuite.finalize} hashes whatever it is given, and {@code OpaqueEnvelope.store}
   * never sees the password at all. So a closed state produced a complete, valid registration
   * record and the client uploaded it.
   *
   * <p><strong>What that record costs is a permanent lockout, not an authentication bypass.</strong>
   * The obvious reading — the account is now registered under the all-zero password, so anyone can
   * log in with it — is wrong, and a review draft of this comment said it before the reproduction
   * in {@code ClosedStateRefusalTest} contradicted it. The two halves of the OPRF disagree. The
   * evaluated element the server returned was computed from {@code blind · H(realPassword)}, fixed
   * at request time and untouched by {@code close()}, while {@code Finalize} consumed zeroes. The
   * stored envelope is therefore keyed by {@code H(zeros || k · H(realPassword))}, and an ordinary
   * login with any password {@code P} produces {@code H(P || k · H(P))}. Matching the two would
   * require {@code P} to be the all-zero string and the real password simultaneously.
   *
   * <p>So the account opens for no password at all — not an attacker's, not the legitimate user's —
   * and no self-service path restores it, because {@code changePassword} needs a JWT from a
   * successful {@code authenticate} and there is no longer any way to obtain one. Only out-of-band
   * account recovery can, which for a server that has not configured a
   * {@code RecoveryChallenger} means no recovery at all. And because {@code changePassword} runs
   * this same code, the bug on a rotation path destroyed a working account while the server's
   * atomic record replacement and session revocation made it look like a successful rotation.
   *
   * <p>Now {@link #password()} throws {@link ClosedContextException} and no record is produced.
   */
  @Override
  public void close() {
    closed = true;
    Arrays.fill(password, (byte) 0);
  }

  private void assertOpen() {
    if (closed) {
      throw new ClosedContextException(
          "ClientRegistrationState has been closed and its copy of the password zeroed; "
              + "scope the try-with-resources to the whole registration");
    }
  }

  /**
   * Redacts the blind and the password.
   *
   * <p>As a record this printed {@code blind} in full decimal, which is the disclosure the
   * paragraph above on this class describes: blind plus the blinded element in {@code request}
   * recovers {@code H(password)}. Unlike {@link ClientAuthState}, the pairing here needed no
   * second source — both halves sat in the same object, one of them printed. See
   * {@link ClientAuthState#toString()}.
   *
   * <p>Not guarded, so a debugger or log formatter cannot turn a lifetime bug into a second,
   * more confusing failure.
   */
  @Override
  public String toString() {
    return "ClientRegistrationState[blind=<redacted>, password=<redacted>, request="
        + (request == null ? "null" : "present") + ", closed=" + closed + "]";
  }
}
