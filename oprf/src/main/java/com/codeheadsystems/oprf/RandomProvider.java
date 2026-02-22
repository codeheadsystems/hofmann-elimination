package com.codeheadsystems.oprf;

import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.security.SecureRandom;

/**
 * Encapsulates a {@link SecureRandom} instance for injectable random byte generation.
 * Used by {@link OprfCipherSuite} for scalar generation
 * and by OPAQUE for nonce/key generation.
 */
public record RandomProvider(SecureRandom random) {

  /**
   * Creates a RandomConfig with a default {@link SecureRandom}.
   */
  public RandomProvider() {
    this(new SecureRandom());
  }

  /**
   * Generates a random byte array of the given length.
   *
   * @param len the number of random bytes to generate
   * @return a new byte array filled with random bytes
   */
  public byte[] randomBytes(int len) {
    byte[] out = new byte[len];
    random.nextBytes(out);
    return out;
  }
}
