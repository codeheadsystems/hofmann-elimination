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
 * <p>{@code blind} is a {@link BigInteger} and cannot be zeroed at the Java level. It is worth
 * more here than in the authentication flow: {@code blind} together with the server's evaluated
 * element and the password reproduces {@code randomizedPwd}, so it is a per-registration secret
 * rather than a throwaway.
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
