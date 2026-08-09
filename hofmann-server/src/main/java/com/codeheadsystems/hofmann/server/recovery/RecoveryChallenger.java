package com.codeheadsystems.hofmann.server.recovery;

/**
 * SPI for out-of-band identity verification during account recovery.
 * <p>
 * Implement this interface to define how your application sends and verifies
 * recovery challenges (e.g. email codes, SMS OTP, TOTP, admin approval).
 * <p>
 * See {@code RECOVERY.md} for implementation examples and security guidance.
 *
 * <p><strong>Deliver the challenge id if you can.</strong> {@link #sendChallenge(byte[], String)}
 * receives a server-generated id; putting it somewhere the account owner will see it — a recovery
 * link is the usual shape — is what closes the targeted account-recovery lockout described below.
 * The two-argument methods remain the interface's required surface so existing implementations
 * keep working, but a deployment that never delivers the id carries a real residual.
 *
 * <p>There is no capability flag to set, and deliberately so. An earlier design had one, and it
 * was a trap: declaring it told the server to key a rate limiter on the id, but the server had no
 * way to tell an issued id from a fabricated one — only this interface could, and the limiter runs
 * first. Declaring it without genuinely binding the id would have handed every guess its own
 * budget. The server now records the ids it issues and checks them itself, so delivering the id is
 * all that is asked of you, and failing to deliver it costs the protection rather than weakening
 * anything.
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
 * a value the server generates, records, and delivers <em>out of band</em>: the challenge id. It
 * reaches the account owner's mailbox and nowhere else, so keying the verification limiter on it
 * means an attacker spends their own budget, not the victim's. Guessing someone else's costs them
 * 122 bits. An id the server never issued is refused as a limiter key, so fabricating them buys
 * nothing.
 *
 * <p>What remains, and is inherent: an attacker can still make {@code recoveryStart} send
 * challenge messages to a victim, and that is still identifier-keyed, so they can still exhaust a
 * victim's <em>start</em> budget. The harm is bounded to "cannot request a new challenge for a
 * while" rather than "cannot complete a recovery already in progress", and it is the price of
 * letting an unauthenticated caller trigger an email at all.
 *
 * <p>The challenge-id design, the two ways to opt in wrongly, and the accepted attribution
 * oracle are recorded in {@code docs/adr/0003-recovery-challenge-id-binding.md}.
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
   * <p><strong>Check that the response belongs to the challenge named by {@code challengeId} and
   * that the challenge belongs to {@code credentialIdentifier}.</strong> Both halves are yours.
   * Without the first, a caller could pair a stolen or replayed code with an id of their choosing;
   * without the second, a caller holding a genuine id for their own account could present it
   * against someone else's identifier and have you check their guess against the victim's code.
   *
   * <p>The server refuses a request whose id it issued for a different credential, so that
   * particular route is closed before you see it — but treat that as defence in depth rather than
   * a guarantee to lean on. It cannot help at all if the id is one the server never recorded,
   * which is the normal case on a multi-node deployment with an unshared
   * {@code RecoveryChallengeStore}. An earlier version of this javadoc promised the server had
   * already made this check; it had not, and an implementer who believed it would have skipped
   * the check that stops the attack.
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
