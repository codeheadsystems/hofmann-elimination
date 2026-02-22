package com.codeheadsystems.rfc.opaque.model;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side state during registration: { blind, password, request }.
 * <p>
 * Implements {@link AutoCloseable} so callers can use try-with-resources to zero the
 * password byte array after use. The {@code blind} BigInteger field is immutable and
 * cannot be zeroed at the Java level.
 */
public record ClientRegistrationState(BigInteger blind, byte[] password, RegistrationRequest request)
    implements AutoCloseable {

  @Override
  public void close() {
    Arrays.fill(password, (byte) 0);
  }
}
