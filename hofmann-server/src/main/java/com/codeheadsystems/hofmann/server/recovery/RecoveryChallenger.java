package com.codeheadsystems.hofmann.server.recovery;

/**
 * SPI for out-of-band identity verification during account recovery.
 * <p>
 * Implement this interface to define how your application sends and verifies
 * recovery challenges (e.g. email codes, SMS OTP, TOTP, admin approval).
 * <p>
 * See {@code RECOVERY.md} for implementation examples and security guidance.
 *
 * <p><strong>Implement the challenge-id methods if you can.</strong> The three-argument
 * {@link #sendChallenge(byte[], String)} and {@link #verifyResponse(byte[], String, String)},
 * together with {@link #bindsChallengeId()} returning true, are what close the targeted
 * account-recovery lockout described below. The two-argument methods remain the interface's
 * required surface so existing implementations keep working, but a deployment using only those
 * carries a real residual.
 *
 * <h2>The lockout, and why the challenge id closes it</h2>
 *
 * <p>{@code recoveryStart} and {@code recoveryVerify} are unauthenticated, and the only thing the
 * caller supplies is the credential identifier. Rate-limiting on that identifier is right for
 * bounding guessing against one account and wrong given who the caller might be: a handful of
 * requests naming a victim spend <em>that victim's</em> budget, and the victim is locked out of
 * recovery without ever having been involved.
 *
 * <p>It cannot be fixed by rate-limiting differently. Before a challenge exists there is nothing
 * to key on that an attacker cannot also supply — which is the whole difficulty. What breaks it is
 * a value the server generates and delivers <em>out of band</em>: the challenge id. It reaches the
 * account owner's mailbox and nowhere else, so keying the verification limiter on it means an
 * attacker spends their own budget, not the victim's. Guessing someone else's costs them 122 bits.
 *
 * <p>What remains, and is inherent: an attacker can still make {@code recoveryStart} send
 * challenge messages to a victim, and that is still identifier-keyed, so they can still exhaust a
 * victim's <em>start</em> budget. The harm is bounded to "cannot request a new challenge for a
 * while" rather than "cannot complete a recovery already in progress", and it is the price of
 * letting an unauthenticated caller trigger an email at all.
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

  /**
   * Whether this challenger delivers the challenge id out of band and binds it to the challenge.
   *
   * <p>Return true only if {@link #sendChallenge(byte[], String)} actually puts the id somewhere
   * the account owner will see it — in the recovery link, or alongside the code — and
   * {@link #verifyResponse(byte[], String, String)} checks the response against <em>that</em>
   * challenge. Returning true without delivering it makes recovery unusable, because the client
   * cannot present an id it never received. Returning true without binding it is worse than
   * useless: the limiter would key on a value the attacker can pick freely, giving each guess its
   * own budget.
   *
   * <p>False, the default, keeps the identifier-keyed behaviour and the lockout residual.
   *
   * @return true if the challenge id is delivered out of band and bound to the challenge
   */
  default boolean bindsChallengeId() {
    return false;
  }

  /**
   * Sends an out-of-band challenge carrying a server-generated challenge id.
   *
   * <p>The id is unguessable and single-purpose. Deliver it to the user along with the challenge —
   * embedded in a recovery link is the usual shape — so the client can present it at
   * verification. Everything said about not revealing whether the credential exists applies here
   * unchanged.
   *
   * <p>The default ignores the id and delegates, so an existing implementation compiles and
   * behaves exactly as before.
   *
   * @param credentialIdentifier raw credential identifier bytes
   * @param challengeId          server-generated identifier for this challenge
   */
  default void sendChallenge(byte[] credentialIdentifier, String challengeId) {
    sendChallenge(credentialIdentifier);
  }

  /**
   * Verifies a challenge response against a specific challenge.
   *
   * <p>An implementation that returns true from {@link #bindsChallengeId()} must check that the
   * response belongs to the challenge named by {@code challengeId}, and not merely that it is a
   * valid response for the identifier. Without that binding a caller could pair a stolen or
   * replayed code with an id of their choosing.
   *
   * <p>The default ignores the id and delegates.
   *
   * @param credentialIdentifier raw credential identifier bytes
   * @param challengeId          the challenge id presented by the client
   * @param challengeResponse    the user's response
   * @return true if the response is valid for that challenge
   */
  default boolean verifyResponse(byte[] credentialIdentifier, String challengeId,
                                 String challengeResponse) {
    return verifyResponse(credentialIdentifier, challengeResponse);
  }
}
