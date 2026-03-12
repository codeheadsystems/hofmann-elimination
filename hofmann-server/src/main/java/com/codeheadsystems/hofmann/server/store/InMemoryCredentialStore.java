package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
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
  private final ConcurrentHashMap<ByteKey, VersionedCredential> store = new ConcurrentHashMap<>();

  /**
   * Instantiates a new In memory credential store.
   */
  public InMemoryCredentialStore() {
    log.warn("Using InMemoryCredentialStore — registrations will NOT survive restarts. "
        + "Replace with a persistent CredentialStore for production.");
  }

  @Override
  public void store(byte[] credentialIdentifier, RegistrationRecord record) {
    store(credentialIdentifier, record, 0);
  }

  @Override
  public void store(byte[] credentialIdentifier, RegistrationRecord record, int keyVersion) {
    store.put(new ByteKey(credentialIdentifier), new VersionedCredential(keyVersion, record));
    log.debug("Stored registration for credential identifier ({} bytes), keyVersion={}",
        credentialIdentifier.length, keyVersion);
  }

  @Override
  public Optional<RegistrationRecord> load(byte[] credentialIdentifier) {
    VersionedCredential vc = store.get(new ByteKey(credentialIdentifier));
    return vc == null ? Optional.empty() : Optional.of(vc.record());
  }

  @Override
  public Optional<VersionedCredential> loadVersioned(byte[] credentialIdentifier) {
    return Optional.ofNullable(store.get(new ByteKey(credentialIdentifier)));
  }

  @Override
  public void delete(byte[] credentialIdentifier) {
    store.remove(new ByteKey(credentialIdentifier));
  }

  // Wrapper so byte[] can be used as a map key with correct equals/hashCode.
  private record ByteKey(byte[] bytes) {

    @Override
    public boolean equals(Object o) {
      return o instanceof ByteKey(byte[] bytes1) && Arrays.equals(bytes, bytes1);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(bytes);
    }
  }
}
