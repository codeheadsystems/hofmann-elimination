package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for KE1 — the first message the client sends during OPAQUE authentication
 * (RFC 9807 §5.2 — AKE message 1).
 * <p>
 * Authentication in OPAQUE-3DH is a three-message authenticated key exchange (AKE).
 * This message (KE1) carries both the credential request and the client's AKE contribution:
 * <ul>
 *   <li>The <em>blinded element</em> is the client's OPRF input (password blinded with a
 *       random scalar), exactly as in registration.  The server evaluates the OPRF so the
 *       client can re-derive {@code randomized_pwd} and recover the envelope.</li>
 *   <li>The <em>client nonce</em> is a fresh random value that binds this AKE session;
 *       it is included in the key-derivation transcript to prevent replay attacks.</li>
 *   <li>The <em>client AKE public key</em> is the ephemeral Diffie-Hellman public key the
 *       client generates for this session.  Together with the server's ephemeral key (in KE2),
 *       it forms the 3DH handshake that produces the shared session key.</li>
 * </ul>
 * All byte array fields are base64-encoded for JSON transport.
 * <p>
 * Used by: {@code POST /opaque/auth/start}
 *
 * @param credentialIdentifierBase64  base64-encoded credential identifier used by the server
 *                                    to look up the stored registration record
 * @param blindedElementBase64        base64-encoded blinded OPRF input element (compressed SEC1 EC point)
 * @param clientNonceBase64           base64-encoded 32-byte random client nonce for this AKE session
 * @param clientAkePublicKeyBase64    base64-encoded ephemeral client AKE public key (compressed SEC1 EC point)
 */
public record AuthStartRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64,
    @JsonProperty("blindedElement") String blindedElementBase64,
    @JsonProperty("clientNonce") String clientNonceBase64,
    @JsonProperty("clientAkePublicKey") String clientAkePublicKeyBase64) {
}
