package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent in-memory {@link SessionStore} backed by a {@link ConcurrentHashMap}.
 * <p>
 * Expired sessions are reaped by a background thread and also evicted lazily on
 * {@link #load}. All sessions are lost on server restart. Suitable for development
 * and integration testing only.
 * <p>
 * <strong>Concurrency:</strong> the reverse index is the synchronisation point. Every
 * update that must keep {@code store} and {@code credentialToJtis} consistent runs inside
 * a {@code compute}/{@code computeIfPresent} on {@code credentialToJtis}, so all operations
 * touching a single credential are serialised by that map's per-bin lock. See
 * {@link #revokeByCredentialIdentifier} for why this matters.
 */
public class InMemorySessionStore implements SessionStore {

  private static final Logger log = LoggerFactory.getLogger(InMemorySessionStore.class);

  /**
   * Default maximum concurrent sessions.
   */
  public static final int DEFAULT_MAX_SESSIONS = 50_000;

  /**
   * Default interval between reaper sweeps (seconds).
   */
  public static final long DEFAULT_REAP_INTERVAL_SECONDS = 60;

  private final int maxSessions;
  private final ConcurrentHashMap<String, SessionData> store = new ConcurrentHashMap<>();
  // Reverse index: credentialIdentifierBase64 → set of jtis, kept in sync with store.
  private final ConcurrentHashMap<String, Set<String>> credentialToJtis = new ConcurrentHashMap<>();
  private final ScheduledExecutorService reaper;

  /**
   * Creates a store with the default capacity (50,000) and reap interval (60s).
   */
  public InMemorySessionStore() {
    this(DEFAULT_MAX_SESSIONS, DEFAULT_REAP_INTERVAL_SECONDS);
  }

  /**
   * Creates a store with a custom capacity and reap interval.
   *
   * @param maxSessions          maximum concurrent sessions
   * @param reapIntervalSeconds  interval between sweeps for expired sessions
   */
  public InMemorySessionStore(int maxSessions, long reapIntervalSeconds) {
    this.maxSessions = maxSessions;
    this.reaper = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "session-reaper");
      t.setDaemon(true);
      return t;
    });
    // Guard the period so a short interval in tests cannot produce a zero period,
    // which scheduleAtFixedRate rejects with IllegalArgumentException.
    long period = Math.max(1, reapIntervalSeconds);
    reaper.scheduleAtFixedRate(this::evictExpired, period, period, TimeUnit.SECONDS);
  }

  @Override
  public void store(String jti, SessionData sessionData) {
    if (store.size() >= maxSessions) {
      // Reclaim before refusing, as the pending-session store does. Sessions here live for the
      // full JWT TTL and are only removed on explicit revoke or expiry, so at capacity most of
      // what is resident is usually already dead — refusing without sweeping first would deny a
      // token to a client that has already completed a valid handshake.
      evictExpired();
      if (store.size() >= maxSessions) {
        log.warn("Session store at capacity ({} entries) after reclaiming expired entries; "
            + "refusing to issue further sessions. Sustained occurrences mean tokens are being "
            + "issued faster than their TTL retires them.", maxSessions);
        throw new IllegalStateException("Too many active sessions");
      }
    }
    // Both maps are updated inside the compute so this cannot interleave with a concurrent
    // revokeByCredentialIdentifier for the same credential.
    credentialToJtis.compute(sessionData.credentialIdentifier(), (k, jtis) -> {
      Set<String> set = jtis == null ? ConcurrentHashMap.newKeySet() : jtis;
      set.add(jti);
      store.put(jti, sessionData);
      return set;
    });
    log.debug("Stored session jti={}", jti);
  }

  @Override
  public Optional<SessionData> load(String jti) {
    SessionData data = store.get(jti);
    if (data == null) {
      return Optional.empty();
    }
    if (data.expiresAt().isBefore(Instant.now())) {
      store.remove(jti);
      // Keep the reverse index in sync on lazy expiry, otherwise stale jtis
      // accumulate unbounded for sessions that expire without an explicit revoke.
      removeFromIndex(data.credentialIdentifier(), jti);
      return Optional.empty();
    }
    return Optional.of(data);
  }

  @Override
  public void revoke(String jti) {
    SessionData data = store.remove(jti);
    if (data != null) {
      removeFromIndex(data.credentialIdentifier(), jti);
    }
    log.debug("Revoked session jti={}", jti);
  }

  /**
   * Removes a jti from the reverse index, dropping the credential's set entirely
   * once it becomes empty so the index does not grow without bound.
   * <p>
   * Callers remove from {@code store} first. Removing in that order can never orphan a
   * jti: the entry is gone from {@code store} before it leaves the index, so a concurrent
   * {@link #revokeByCredentialIdentifier} that misses it has nothing left to revoke.
   */
  private void removeFromIndex(String credentialIdentifier, String jti) {
    credentialToJtis.computeIfPresent(credentialIdentifier, (k, jtis) -> {
      jtis.remove(jti);
      return jtis.isEmpty() ? null : jtis;
    });
  }

  @Override
  public void revokeByCredentialIdentifier(String credentialIdentifierBase64) {
    // Drain inside the compute rather than removing the set and then draining it. The old
    // two-step form raced with store(): a store() that had already read the set could add its
    // jti after the drain, leaving that jti live in `store` but absent from the index — so it
    // survived this revocation and, because the next store() creates a fresh set, every future
    // one as well. Holding the bin lock across the drain forces a concurrent store() to fall
    // entirely before it (its jti is drained) or entirely after (its jti is correctly indexed).
    credentialToJtis.compute(credentialIdentifierBase64, (k, jtis) -> {
      if (jtis != null) {
        jtis.forEach(store::remove);
        log.debug("Revoked {} session(s) for credential", jtis.size());
      }
      return null;
    });
  }

  /** Drops every entry past its expiry, keeping the reverse index in step. */
  private void evictExpired() {
    Instant now = Instant.now();
    store.forEach((jti, data) -> {
      if (data.expiresAt().isBefore(now)) {
        store.remove(jti);
        removeFromIndex(data.credentialIdentifier(), jti);
      }
    });
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }
}
