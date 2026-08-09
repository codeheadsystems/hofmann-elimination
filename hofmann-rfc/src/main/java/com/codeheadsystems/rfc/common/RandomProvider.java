package com.codeheadsystems.rfc.common;

import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.security.SecureRandom;

/**
 * Encapsulates a {@link SecureRandom} instance for injectable random byte generation.
 * Used by {@link OprfCipherSuite} for scalar generation
 * and by OPAQUE for nonce/key generation.
 *
 * @param random the source. Injectable so an operator can install an HSM- or PKCS#11-backed
 *               {@link SecureRandom}; the unavoidable consequence is that a stub whose
 *               {@code nextBytes} ignores its buffer is equally installable, and nothing at this
 *               layer can tell the two apart */
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
