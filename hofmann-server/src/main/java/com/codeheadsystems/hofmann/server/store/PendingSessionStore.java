package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import java.util.Optional;

/**
 * Storage abstraction for pending OPAQUE authentication sessions (between authStart and authFinish).
 * <p>
 * During the OPAQUE AKE protocol, the server generates a KE2 response in authStart and must
 * retain the corresponding {@link ServerAuthState} until the client submits KE3 in authFinish.
 * This store holds that ephemeral state, keyed by a random session token.
 * <p>
 * Implementations must be thread-safe and should enforce a TTL to prevent unbounded growth
 * from abandoned sessions (clients that never call authFinish).
 * <p>
 * <strong>Clustering:</strong> the default {@link InMemoryPendingSessionStore} is suitable for
 * single-node deployments only. In a multi-node cluster, authStart and authFinish may be
 * routed to different nodes, so a distributed implementation (e.g. Redis-backed) is required
 * unless sticky sessions are configured at the load balancer.
 */
public interface PendingSessionStore {

  /**
   * Stores a pending authentication session.
   *
   * @param sessionToken              unique token identifying this session (returned to the client)
   * @param state                     the server-side auth state to retain
   * @param credentialIdentifierBase64 base64-encoded credential identifier for the authenticating user
   * @throws IllegalStateException if the store has reached its capacity limit
   */
  void store(String sessionToken, ServerAuthState state, String credentialIdentifierBase64);

  /**
   * Retrieves and atomically removes a pending session.
   * <p>
   * Returns empty if the session token is not found or has expired.
   * The session is always removed on a successful retrieval (consume-once semantics).
   *
   * @param sessionToken the session token
   * @return the pending session data, or empty if not found or expired
   */
  Optional<PendingSession> remove(String sessionToken);

  /**
   * Shuts down any background resources (e.g. reaper threads).
   * Called on application shutdown.
   */
  default void shutdown() {
  }

  /**
   * Data held for a pending authentication session.
   *
   * @param state                     the server auth state
   * @param credentialIdentifierBase64 base64-encoded credential identifier
   */
  record PendingSession(ServerAuthState state, String credentialIdentifierBase64) {
  }
}
