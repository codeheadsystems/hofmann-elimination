package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import java.util.Optional;

/**
 * Storage abstraction for OPAQUE registration records.
 * <p>
 * Implementations must be thread-safe. Typical production implementations back
 * this with a relational or key-value database.
 * <p>
 * <strong>Key rotation support:</strong> the versioned methods ({@link #store(byte[], RegistrationRecord, int)}
 * and {@link #loadVersioned(byte[])}) enable OPAQUE key rotation by tracking which server key
 * version each credential was registered with. The default implementations delegate to the
 * unversioned methods with version 0, so existing {@code CredentialStore} implementations
 * continue to work without changes. Override the versioned methods to persist the key version
 * (e.g. a {@code key_version} column in your database).
 */
public interface CredentialStore {

  /**
   * Stores or replaces the registration record for the given credential identifier.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   * @param record               the registration record produced at the end of client registration
   */
  void store(byte[] credentialIdentifier, RegistrationRecord record);

  /**
   * Stores or replaces the registration record with a specific key version.
   * <p>
   * Override this method to persist the key version alongside the record (e.g. a
   * {@code key_version} column). The default implementation delegates to
   * {@link #store(byte[], RegistrationRecord)} and discards the version.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   * @param record               the registration record
   * @param keyVersion           the server key version this credential is registered with
   */
  default void store(byte[] credentialIdentifier, RegistrationRecord record, int keyVersion) {
    store(credentialIdentifier, record);
  }

  /**
   * Retrieves the registration record for the given credential identifier.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   * @return the stored record, or empty if the credential identifier is not registered
   */
  Optional<RegistrationRecord> load(byte[] credentialIdentifier);

  /**
   * Retrieves the registration record with its key version.
   * <p>
   * Override this method to return the persisted key version. The default implementation
   * delegates to {@link #load(byte[])} and wraps the result with version 0.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   * @return the versioned credential, or empty if not registered
   */
  default Optional<VersionedCredential> loadVersioned(byte[] credentialIdentifier) {
    return load(credentialIdentifier).map(r -> new VersionedCredential(0, r));
  }

  /**
   * Removes the registration record for the given credential identifier, if present.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   */
  void delete(byte[] credentialIdentifier);
}
