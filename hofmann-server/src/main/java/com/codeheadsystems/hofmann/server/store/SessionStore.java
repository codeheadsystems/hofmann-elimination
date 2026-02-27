package com.codeheadsystems.hofmann.server.store;

import java.util.Optional;

/**
 * Storage abstraction for authenticated sessions.
 * <p>
 * Implementations must be thread-safe.
 * <p>
 * <strong>Credential deletion contract:</strong> when a credential is permanently deleted
 * from the system, <em>all</em> active sessions for that credential must be revoked so that
 * any JWT tokens issued before the deletion stop being accepted immediately. Implementations
 * must maintain whatever index is necessary to support
 * {@link #revokeByCredentialIdentifier(String)} efficiently; a full-store scan on every
 * deletion is not acceptable under load.
 */
public interface SessionStore {

  /**
   * Stores session data keyed by the JWT ID (jti).
   *
   * @param jti         unique token identifier
   * @param sessionData session data to store
   */
  void store(String jti, SessionData sessionData);

  /**
   * Loads session data by JWT ID, returning empty if not found or expired.
   *
   * @param jti unique token identifier
   * @return the session data, or empty if not found or expired
   */
  Optional<SessionData> load(String jti);

  /**
   * Revokes a single session by JWT ID.
   *
   * @param jti unique token identifier
   */
  void revoke(String jti);

  /**
   * Revokes <em>all</em> active sessions belonging to the given credential identifier.
   * <p>
   * This must be called whenever a credential is deleted so that previously issued JWT tokens
   * for that credential are immediately invalidated. Failing to do so allows a deleted user's
   * tokens to remain valid until they naturally expire, which is a security violation.
   * <p>
   * The {@code credentialIdentifierBase64} value must be the base64-encoded form of the raw
   * credential identifier bytes — exactly the value stored in
   * {@link SessionData#credentialIdentifier()}.
   * <p>
   * Implementations must handle the case where no sessions exist for the given credential
   * without throwing an exception.
   *
   * @param credentialIdentifierBase64 base64-encoded credential identifier whose sessions
   *                                   should all be revoked
   */
  void revokeByCredentialIdentifier(String credentialIdentifierBase64);
}
