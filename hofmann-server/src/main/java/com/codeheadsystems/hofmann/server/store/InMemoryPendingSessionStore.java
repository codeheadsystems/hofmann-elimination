package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent in-memory {@link PendingSessionStore} backed by a {@link ConcurrentHashMap}.
 * <p>
 * Expired sessions are reaped by a background thread. All sessions are lost on server restart.
 * Suitable for single-node deployments, development, and integration testing.
 * <p>
 * For multi-node clusters, implement {@link PendingSessionStore} with a distributed backend
 * (e.g. Redis with TTL) so that authStart on one node and authFinish on another can share state.
 */
public class InMemoryPendingSessionStore implements PendingSessionStore {

  private static final Logger log = LoggerFactory.getLogger(InMemoryPendingSessionStore.class);

  /**
   * Default TTL for pending sessions (seconds).
   */
  public static final long DEFAULT_TTL_SECONDS = 120;

  /**
   * Default maximum concurrent pending sessions.
   */
  public static final int DEFAULT_MAX_SESSIONS = 10_000;

  private final long ttlSeconds;
  private final int maxSessions;
  private final ConcurrentHashMap<String, TimestampedEntry> sessions = new ConcurrentHashMap<>();
  private final ScheduledExecutorService reaper;

  /**
   * Creates a store with default TTL (120s) and capacity (10,000).
   */
  public InMemoryPendingSessionStore() {
    this(DEFAULT_TTL_SECONDS, DEFAULT_MAX_SESSIONS);
  }

  /**
   * Creates a store with custom TTL and capacity.
   *
   * @param ttlSeconds  time-to-live for pending sessions
   * @param maxSessions maximum concurrent pending sessions
   */
  public InMemoryPendingSessionStore(long ttlSeconds, int maxSessions) {
    this.ttlSeconds = ttlSeconds;
    this.maxSessions = maxSessions;
    this.reaper = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "pending-session-reaper");
      t.setDaemon(true);
      return t;
    });
    reaper.scheduleAtFixedRate(
        () -> {
          Instant cutoff = Instant.now().minusSeconds(ttlSeconds);
          sessions.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
        }, ttlSeconds, ttlSeconds / 4, TimeUnit.SECONDS);
  }

  @Override
  public void store(String sessionToken, ServerAuthState state, String credentialIdentifierBase64) {
    store(sessionToken, state, credentialIdentifierBase64, 0);
  }

  @Override
  public void store(String sessionToken, ServerAuthState state,
                    String credentialIdentifierBase64, int keyVersion) {
    if (sessions.size() >= maxSessions) {
      throw new IllegalStateException("Too many pending sessions");
    }
    sessions.put(sessionToken,
        new TimestampedEntry(state, credentialIdentifierBase64, keyVersion, Instant.now()));
    log.debug("Stored pending session {}", sessionToken);
  }

  @Override
  public Optional<PendingSession> remove(String sessionToken) {
    TimestampedEntry entry = sessions.remove(sessionToken);
    if (entry == null) {
      return Optional.empty();
    }
    if (entry.createdAt().isBefore(Instant.now().minusSeconds(ttlSeconds))) {
      return Optional.empty();
    }
    return Optional.of(new PendingSession(entry.state(), entry.credentialIdentifierBase64(),
        entry.keyVersion()));
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }

  private record TimestampedEntry(
      ServerAuthState state,
      String credentialIdentifierBase64,
      int keyVersion,
      Instant createdAt) {
  }
}
