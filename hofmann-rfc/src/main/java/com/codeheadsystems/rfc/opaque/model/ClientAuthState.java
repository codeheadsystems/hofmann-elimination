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
 * It is a {@link BigInteger}, and taken together with the {@code ke1} held in this same record it
 * is a password verifier: {@code blindedElement = blind · H(password)}, so anyone holding both
 * recovers {@code H(password)} as {@code blind⁻¹ · blindedElement} and can then run an offline
 * dictionary attack. Denying exactly that is what OPAQUE is for. An earlier version of this
 * comment called {@code blind} a password-independent per-exchange secret and the residue a
 * linkability concern; that was wrong, and a reviewer demonstrated password recovery from these
 * two fields alone. {@code clientAkePrivateKey} is the milder case the old text described.
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
