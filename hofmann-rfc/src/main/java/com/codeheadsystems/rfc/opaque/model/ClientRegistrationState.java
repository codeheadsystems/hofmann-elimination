package com.codeheadsystems.rfc.opaque.model;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side state during registration: { blind, password, request }.
 *
 * <p><strong>The password is copied on construction, and {@link #close()} zeroes the copy.</strong>
 * See {@link ClientAuthState} for why the previous by-reference behaviour made the
 * {@link AutoCloseable} unusable in practice, and therefore unused.
 *
 * <p><strong>The caller still owns its own array.</strong> This zeroes what it copied, not what it
 * was given.
 *
 * <p><strong>{@code blind} cannot be zeroed, and it is a password verifier.</strong> It is a
 * {@link BigInteger}, and with the {@code request} held in this same record —
 * {@code blindedElement = blind · H(password)} — anyone holding both recovers {@code H(password)}
 * and can mount an offline dictionary attack without the server. That is a stronger statement
 * than the earlier one here, which said {@code blind} plus the evaluated element plus
 * <em>the password</em> reproduces {@code randomizedPwd}; the real attack needs no password at
 * all. See {@link ClientAuthState} for the same point and for why clearing the array is defence
 * in depth rather than a guarantee.
 */
public record ClientRegistrationState(BigInteger blind, byte[] password, RegistrationRequest request)
    implements AutoCloseable {

  /**
   * Copies the password so this record's lifetime is independent of the caller's array.
   *
   * @param blind    the OPRF blind
   * @param password the password; copied, not retained
   * @param request  the registration request
   */
  public ClientRegistrationState {
    password = password.clone();
  }

  @Override
  public void close() {
    Arrays.fill(password, (byte) 0);
  }
}
