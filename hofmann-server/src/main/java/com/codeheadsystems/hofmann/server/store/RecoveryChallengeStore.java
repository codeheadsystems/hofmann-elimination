package com.codeheadsystems.hofmann.server.store;

import java.util.Optional;

/**
 * Records the challenge ids the server issued during {@code recoveryStart}.
 *
 * <p>This exists so the verification rate limiter can key on a value the <em>server</em> chose.
 * Without it the manager has no way to tell an issued challenge id from one an attacker made up:
 * it generated the id, handed it to the challenger, and forgot it. Keying a limiter on such a
 * value gives every fabricated id its own bucket — an unbounded key dimension, and a guessing
 * budget that resets on demand.
 *
 * <p>That is also why the alternative — asking the {@code RecoveryChallenger} to vouch for the id
 * — does not work. The challenger is the only party that could, and the limiter has to run before
 * it. Delegating the one check that gives the limiter key its meaning is what made the earlier
 * capability-flag design a footgun that documentation could not close.
 *
 * <p>Implementations must be thread-safe, and should enforce a TTL and a capacity limit. A
 * challenge id is not a credential — it authorises nothing on its own, and possessing one only
 * lets the holder spend that challenge's own verification budget — so it does not need the
 * single-use consume semantics {@link RecoveryTokenStore} has.
 *
 * <p><strong>Clustering:</strong> the default {@link InMemoryRecoveryChallengeStore} is
 * single-node. In a cluster where {@code recoveryStart} and {@code recoveryVerify} can land on
 * different nodes, an unshared store means the id is unknown on the verifying node and the limiter
 * falls back to identifier keying — the lockout returns, quietly. Back it with the same
 * distributed store as the recovery tokens.
 */
public interface RecoveryChallengeStore {

  /**
   * Records an issued challenge id and the credential it was issued for.
   *
   * @param challengeId                the server-generated challenge id
   * @param credentialIdentifierBase64 the credential the challenge was issued for
   */
  void store(String challengeId, String credentialIdentifierBase64);

  /**
   * Returns the credential a challenge id was issued for, without consuming it.
   *
   * <p>Non-consuming on purpose: a user may legitimately retry verification after a mistyped
   * code, and consuming here would turn a typo into a restarted recovery.
   *
   * @param challengeId the challenge id presented by the client
   * @return the credential identifier, or empty if the id is unknown or expired
   */
  Optional<String> peek(String challengeId);

  /**
   * Releases any resources held by this store, such as an expiry reaper.
   */
  default void shutdown() {
  }
}
