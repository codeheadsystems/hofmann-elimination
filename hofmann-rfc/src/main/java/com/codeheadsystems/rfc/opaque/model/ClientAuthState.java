package com.codeheadsystems.rfc.opaque.model;

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
 * invoked anywhere, and for the life of this record it never was: it was a mitigation that
 * existed but did not run. Copying decouples the two lifetimes, and the callers now close.
 *
 * <p>The cost is one extra copy of the password on the heap for the duration of the exchange.
 * That is the right trade: the copy is bounded and zeroed at a known point, whereas the caller's
 * array has a lifetime this class cannot see.
 *
 * <p><strong>The caller still owns its own array.</strong> This zeroes what it copied, not what it
 * was given. A caller that wants its own buffer cleared must do that itself.
 *
 * <p>{@code blind} and {@code clientAkePrivateKey} are {@link BigInteger} and cannot be zeroed at
 * the Java level; both are password-independent per-exchange secrets, so what remains is a
 * transcript-linkability exposure rather than a password one.
 */
public record ClientAuthState(BigInteger blind, byte[] password, KE1 ke1, BigInteger clientAkePrivateKey)
    implements AutoCloseable {

  /**
   * Copies the password so this record's lifetime is independent of the caller's array.
   *
   * @param blind               the OPRF blind
   * @param password            the password; copied, not retained
   * @param ke1                 the KE1 message
   * @param clientAkePrivateKey the client ephemeral AKE private key
   */
  public ClientAuthState {
    password = password.clone();
  }

  @Override
  public void close() {
    Arrays.fill(password, (byte) 0);
  }
}
