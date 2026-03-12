package com.codeheadsystems.hofmann.server.store;

import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;

/**
 * A registration record paired with the key version it was created under.
 * <p>
 * Used by {@link CredentialStore#loadVersioned(byte[])} to support OPAQUE key rotation.
 * The {@code keyVersion} tells the server which key pair to use for authentication,
 * since credentials are cryptographically bound to the server keys that were active
 * at registration time.
 *
 * @param keyVersion the server key version this credential was registered with
 * @param record     the OPAQUE registration record
 */
public record VersionedCredential(int keyVersion, RegistrationRecord record) {
}
