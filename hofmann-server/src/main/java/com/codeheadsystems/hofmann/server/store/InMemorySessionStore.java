package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent in-memory {@link SessionStore} backed by a {@link ConcurrentHashMap}.
 * <p>
 * Expired sessions are lazily evicted on {@link #load}. All sessions are lost on
 * server restart. Suitable for development and integration testing only.
 */
public class InMemorySessionStore implements SessionStore {

  private static final Logger log = LoggerFactory.getLogger(InMemorySessionStore.class);

  private final ConcurrentHashMap<String, SessionData> store = new ConcurrentHashMap<>();

  @Override
  public void store(String jti, SessionData sessionData) {
    store.put(jti, sessionData);
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
      return Optional.empty();
    }
    return Optional.of(data);
  }

  @Override
  public void revoke(String jti) {
    store.remove(jti);
    log.debug("Revoked session jti={}", jti);
  }
}
