package com.codeheadsystems.rfc.opaque.model;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side state during authentication: { blind, password, ke1, clientAkePrivateKey }.
 * <p>
 * Implements {@link AutoCloseable} so callers can use try-with-resources to zero the
 * password byte array after use. The {@code blind} and {@code clientAkePrivateKey}
 * BigInteger fields are immutable and cannot be zeroed at the Java level.
 */
public record ClientAuthState(BigInteger blind, byte[] password, KE1 ke1, BigInteger clientAkePrivateKey)
    implements AutoCloseable {

  @Override
  public void close() {
    Arrays.fill(password, (byte) 0);
  }
}
