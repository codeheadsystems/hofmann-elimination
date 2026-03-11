package com.codeheadsystems.hofmann.server.manager;

/**
 * Encapsulates the current JWT signing key and an optional previous key for verification
 * during key rotation.
 * <p>
 * Modeled after {@link com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail} — a
 * {@code Supplier<JwtKeyDetail>} is injected into {@link JwtManager} so that key material
 * can be rotated at runtime without restarting the server.
 * <p>
 * <strong>Rotation workflow:</strong>
 * <ol>
 *   <li>Generate a new 32-byte secret: {@code openssl rand -hex 32}</li>
 *   <li>Deploy with the new secret as {@code signingKey} and the old secret as {@code previousKey}</li>
 *   <li>New tokens are signed with {@code signingKey}; tokens signed with {@code previousKey}
 *       are still accepted for verification</li>
 *   <li>After one TTL period (all old tokens have expired), remove {@code previousKey}</li>
 * </ol>
 *
 * @param signingKey  the current HMAC-SHA256 signing key (used for signing and verification)
 * @param previousKey the previous signing key (used for verification only during rotation),
 *                    or {@code null} if no rotation is in progress
 */
public record JwtKeyDetail(byte[] signingKey, byte[] previousKey) {

  /**
   * Creates a JwtKeyDetail with only a signing key (no rotation).
   *
   * @param signingKey the HMAC-SHA256 signing key
   */
  public JwtKeyDetail(byte[] signingKey) {
    this(signingKey, null);
  }
}
