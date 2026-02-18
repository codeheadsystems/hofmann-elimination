package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.opaque.model.RegistrationRecord;
import java.util.Optional;

/**
 * Storage abstraction for OPAQUE registration records.
 * <p>
 * Implementations must be thread-safe. Typical production implementations back
 * this with a relational or key-value database.
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
   * Retrieves the registration record for the given credential identifier.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   * @return the stored record, or empty if the credential identifier is not registered
   */
  Optional<RegistrationRecord> load(byte[] credentialIdentifier);

  /**
   * Removes the registration record for the given credential identifier, if present.
   *
   * @param credentialIdentifier opaque byte-string that uniquely identifies the credential
   */
  void delete(byte[] credentialIdentifier);
}
