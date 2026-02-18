package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.opaque.model.RegistrationRecord;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent in-memory {@link CredentialStore} backed by a {@link ConcurrentHashMap}.
 * <p>
 * All registrations are lost on server restart. Suitable for development and
 * integration testing only — replace with a database-backed implementation for production.
 */
public class InMemoryCredentialStore implements CredentialStore {

  private static final Logger log = LoggerFactory.getLogger(InMemoryCredentialStore.class);

  // Wrapper so byte[] can be used as a map key with correct equals/hashCode.
  private record ByteKey(byte[] bytes) {

    @Override
    public boolean equals(Object o) {
      return o instanceof ByteKey other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(bytes);
    }
  }

  private final ConcurrentHashMap<ByteKey, RegistrationRecord> store = new ConcurrentHashMap<>();

  public InMemoryCredentialStore() {
    log.warn("Using InMemoryCredentialStore — registrations will NOT survive restarts. "
        + "Replace with a persistent CredentialStore for production.");
  }

  @Override
  public void store(byte[] credentialIdentifier, RegistrationRecord record) {
    store.put(new ByteKey(credentialIdentifier), record);
    log.debug("Stored registration for credential identifier ({} bytes)", credentialIdentifier.length);
  }

  @Override
  public Optional<RegistrationRecord> load(byte[] credentialIdentifier) {
    return Optional.ofNullable(store.get(new ByteKey(credentialIdentifier)));
  }

  @Override
  public void delete(byte[] credentialIdentifier) {
    store.remove(new ByteKey(credentialIdentifier));
  }
}
