package com.codeheadsystems.oprf;

import java.security.SecureRandom;

/**
 * Encapsulates a {@link SecureRandom} instance for injectable random byte generation.
 * Used by {@link com.codeheadsystems.oprf.rfc9497.OprfCipherSuite} for scalar generation
 * and by OPAQUE for nonce/key generation.
 */
public class RandomConfig {

  private final SecureRandom random;

  /**
   * Creates a RandomConfig with a default {@link SecureRandom}.
   */
  public RandomConfig() {
    this(new SecureRandom());
  }

  /**
   * Creates a RandomConfig with the given {@link SecureRandom}.
   *
   * @param random the random source to use
   */
  public RandomConfig(SecureRandom random) {
    this.random = random;
  }

  /**
   * Returns the underlying {@link SecureRandom}.
   */
  public SecureRandom random() {
    return random;
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
