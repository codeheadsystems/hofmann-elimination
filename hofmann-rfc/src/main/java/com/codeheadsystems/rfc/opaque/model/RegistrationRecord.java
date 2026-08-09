package com.codeheadsystems.rfc.opaque.model;

/**
 * Server-stored registration record: { clientPublicKey, maskingKey, envelope }.
 *
 * <p>This is the whole of what the server keeps for a credential. It is <strong>not</strong> a
 * password verifier: nothing here allows the server, or anyone who steals its database, to check a
 * password guess without running the protocol against the OPRF key. That property is the point of
 * OPAQUE, and it is why this record can be stored in an ordinary table.
 *
 * <p><strong>Validate a record before storing one that arrived over the wire.</strong>
 * {@code Server.validateRegistrationRecord} checks every field's length and, importantly, forces a
 * curve decode of {@code clientPublicKey} — length alone is not enough, because that value is used
 * as a Diffie-Hellman peer element during authentication and must be a real, non-identity point.
 * A {@code CredentialStore} implementation is not the right place to re-check this.
 *
 * @param clientPublicKey the client's long-term public key, {@code Npk} bytes. Used as a DH peer
 *                        element during the AKE, so it must decode to a valid non-identity point
 * @param maskingKey      the key the server uses to mask the credential response, {@code Nh} bytes.
 *                        Masking is what makes a response for an unregistered credential
 *                        indistinguishable in content from a real one
 * @param envelope        the client's encrypted key material, recoverable only with the password
 */
public record RegistrationRecord(byte[] clientPublicKey, byte[] maskingKey, Envelope envelope) {
}
