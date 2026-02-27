package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
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
  // Reverse index: credentialIdentifierBase64 → set of jtis, kept in sync with store.
  private final ConcurrentHashMap<String, Set<String>> credentialToJtis = new ConcurrentHashMap<>();

  @Override
  public void store(String jti, SessionData sessionData) {
    store.put(jti, sessionData);
    credentialToJtis.computeIfAbsent(sessionData.credentialIdentifier(),
        k -> ConcurrentHashMap.newKeySet()).add(jti);
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
    SessionData data = store.remove(jti);
    if (data != null) {
      Set<String> jtis = credentialToJtis.get(data.credentialIdentifier());
      if (jtis != null) {
        jtis.remove(jti);
      }
    }
    log.debug("Revoked session jti={}", jti);
  }

  @Override
  public void revokeByCredentialIdentifier(String credentialIdentifierBase64) {
    Set<String> jtis = credentialToJtis.remove(credentialIdentifierBase64);
    if (jtis != null) {
      jtis.forEach(store::remove);
      log.debug("Revoked {} session(s) for credential", jtis.size());
    }
  }
}
