package com.codeheadsystems.hofmann.server.recovery;

/**
 * SPI for out-of-band identity verification during account recovery.
 * <p>
 * Implement this interface to define how your application sends and verifies
 * recovery challenges (e.g. email codes, SMS OTP, TOTP, admin approval).
 * <p>
 * See {@code RECOVERY.md} for implementation examples and security guidance.
 */
public interface RecoveryChallenger {

  /**
   * Sends an out-of-band challenge to the user identified by credentialIdentifier.
   * <p>
   * This method <strong>must not</strong> reveal whether the credential exists.
   * If the credential is unknown, either silently succeed (recommended) or send
   * a generic "if this account exists, a code was sent" message.
   *
   * @param credentialIdentifier raw credential identifier bytes
   */
  void sendChallenge(byte[] credentialIdentifier);

  /**
   * Verifies the user's response to a previously sent challenge.
   * <p>
   * Implementations should use constant-time comparison (e.g.
   * {@link java.security.MessageDigest#isEqual}) to prevent timing attacks.
   *
   * @param credentialIdentifier raw credential identifier bytes
   * @param challengeResponse    the user's response (e.g. "482901")
   * @return true if the response is valid
   */
  boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse);
}
