package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for the second (final) message the client sends during OPAQUE registration
 * (RFC 9807 §5.1 — RegistrationRecord upload).
 * <p>
 * After the client receives the server's OPRF output and long-term public key, it:
 * <ol>
 *   <li>Derives {@code randomized_pwd} by unblinding the OPRF result.</li>
 *   <li>Derives a client-side AKE key pair from {@code randomized_pwd}.</li>
 *   <li>Seals the client private key inside an <em>envelope</em> — an authenticated
 *       encryption structure (nonce + auth tag) keyed with material derived from
 *       {@code randomized_pwd}.  The server can store the envelope but can never
 *       decrypt it without knowing the password.</li>
 * </ol>
 * The resulting {@link com.codeheadsystems.opaque.model.RegistrationRecord} — composed of
 * the client public key, the masking key, and the envelope — is uploaded here so the server
 * can store it for future authentication attempts.
 * <p>
 * All byte array fields are base64-encoded for JSON transport.
 * <p>
 * Used by: {@code POST /opaque/registration/finish}
 *
 * @param credentialIdentifierBase64 base64-encoded credential identifier (e.g. username or email)
 *                                   used to associate the record with this user on the server
 * @param clientPublicKeyBase64      base64-encoded client AKE public key (compressed SEC1 EC point)
 *                                   derived from {@code randomized_pwd}; stored by the server and
 *                                   used to verify the client during authentication
 * @param maskingKeyBase64           base64-encoded masking key derived from {@code randomized_pwd};
 *                                   used by the server to blind the envelope during authentication,
 *                                   preventing offline dictionary attacks on the stored record
 * @param envelopeNonceBase64        base64-encoded random nonce used to seal the envelope;
 *                                   must be unique per registration to ensure different ciphertexts
 *                                   even for the same password
 * @param authTagBase64              base64-encoded authentication tag for the envelope;
 *                                   verifies the envelope's integrity and authenticates the
 *                                   server's public key bound inside it
 */
public record RegistrationFinishRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64,
    @JsonProperty("clientPublicKey") String clientPublicKeyBase64,
    @JsonProperty("maskingKey") String maskingKeyBase64,
    @JsonProperty("envelopeNonce") String envelopeNonceBase64,
    @JsonProperty("authTag") String authTagBase64) {
}
