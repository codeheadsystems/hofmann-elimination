package com.codeheadsystems.hofmann.server.store;

import java.util.Optional;

/**
 * Storage abstraction for single-use, time-limited account recovery tokens.
 * <p>
 * During account recovery, a verified challenge response produces a recovery token
 * that authorizes re-registration for a specific credential. This store holds those
 * tokens until they are consumed or expire.
 * <p>
 * Implementations must be thread-safe and should enforce a TTL and capacity limit
 * to prevent unbounded growth.
 * <p>
 * <strong>Clustering:</strong> the default {@link InMemoryRecoveryTokenStore} is suitable
 * for single-node deployments only. For multi-node clusters, implement with a distributed
 * backend (e.g. Redis with TTL) so that recovery verify and registration finish can be
 * handled by different nodes.
 */
public interface RecoveryTokenStore {

  /**
   * Stores a recovery token associated with a credential identifier.
   *
   * @param token                      unique recovery token string
   * @param credentialIdentifierBase64 base64-encoded credential identifier
   * @throws IllegalStateException if the store has reached its capacity limit
   */
  void store(String token, String credentialIdentifierBase64);

  /**
   * Retrieves the credential identifier for a recovery token without removing it.
   * <p>
   * Returns empty if the token is not found or has expired.
   * Use this to validate a recovery token during registration start
   * (before the token should be consumed).
   *
   * @param token the recovery token
   * @return the base64-encoded credential identifier, or empty if not found or expired
   */
  Optional<String> peek(String token);

  /**
   * Retrieves and atomically removes a recovery token (consume-once semantics).
   * <p>
   * Returns empty if the token is not found or has expired.
   * The token is always removed on a successful retrieval (single-use).
   *
   * @param token the recovery token
   * @return the base64-encoded credential identifier, or empty if not found or expired
   */
  Optional<String> remove(String token);

  /**
   * Shuts down any background resources (e.g. reaper threads).
   * Called on application shutdown.
   */
  default void shutdown() {
  }
}
