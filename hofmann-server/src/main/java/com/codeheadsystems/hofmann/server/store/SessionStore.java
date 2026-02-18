package com.codeheadsystems.hofmann.server.store;

import java.util.Optional;

/**
 * Storage abstraction for authenticated sessions.
 * <p>
 * Implementations must be thread-safe.
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
   * Revokes a session by removing it from the store.
   *
   * @param jti unique token identifier
   */
  void revoke(String jti);
}
