package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for KE2 — the server's response to the client's KE1 during OPAQUE authentication
 * (RFC 9807 §5.2 — AKE message 2).
 * <p>
 * KE2 is the most complex message in the OPAQUE-3DH flow.  It bundles the server's OPRF
 * evaluation result together with the masked credential envelope and the server's AKE
 * contribution into a single response:
 * <ul>
 *   <li>The <em>evaluated element</em> is the OPRF output, which the client unblinds to
 *       recover {@code randomized_pwd} and decrypt the envelope.</li>
 *   <li>The <em>masking nonce</em> and <em>masked response</em> form the encrypted envelope
 *       delivery: the server XORs the envelope and server public key with a stream derived
 *       from the masking key and a fresh nonce.  This prevents an attacker who observes the
 *       stored record from using it to mount offline dictionary attacks — the masking key is
 *       only recoverable by a client who knows the correct password.</li>
 *   <li>The <em>server nonce</em> is a fresh random value analogous to the client nonce,
 *       binding this session in the transcript.</li>
 *   <li>The <em>server AKE public key</em> is the server's ephemeral DH contribution for
 *       the 3DH handshake.</li>
 *   <li>The <em>server MAC</em> authenticates everything the server has committed to so far.
 *       The client verifies this MAC before computing the client MAC (KE3), ensuring mutual
 *       authentication.</li>
 * </ul>
 * A <em>session token</em> is added as a server-side convenience: it lets the server correlate
 * the matching {@code /auth/finish} request with the AKE state ({@code ServerAuthState}) kept
 * in memory between the two calls.  The token has no cryptographic role and is opaque to
 * the client.
 * <p>
 * All byte array fields are base64-encoded for JSON transport.
 * <p>
 * Used by: {@code POST /opaque/auth/start} response
 *
 * @param sessionToken             server-generated opaque token the client echoes back in
 *                                 {@code /auth/finish} so the server can retrieve its pending AKE state
 * @param evaluatedElementBase64   base64-encoded OPRF-evaluated element (compressed SEC1 EC point)
 * @param maskingNonceBase64       base64-encoded fresh random nonce used to derive the masking stream
 * @param maskedResponseBase64     base64-encoded masked (XOR-encrypted) envelope + server public key
 * @param serverNonceBase64        base64-encoded 32-byte random server nonce for this AKE session
 * @param serverAkePublicKeyBase64 base64-encoded ephemeral server AKE public key (compressed SEC1 EC point)
 * @param serverMacBase64          base64-encoded server MAC authenticating the KE2 transcript
 */
public record AuthStartResponse(
    @JsonProperty("sessionToken") String sessionToken,
    @JsonProperty("evaluatedElement") String evaluatedElementBase64,
    @JsonProperty("maskingNonce") String maskingNonceBase64,
    @JsonProperty("maskedResponse") String maskedResponseBase64,
    @JsonProperty("serverNonce") String serverNonceBase64,
    @JsonProperty("serverAkePublicKey") String serverAkePublicKeyBase64,
    @JsonProperty("serverMac") String serverMacBase64) {
}
