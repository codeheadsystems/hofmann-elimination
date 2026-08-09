package com.codeheadsystems.rfc.opaque.model;

/**
 * Server's credential response: { evaluatedElement, maskingNonce, maskedResponse }.
 *
 * @param evaluatedElement the OPRF evaluation under the credential's key, {@code Ne} bytes
 * @param maskingNonce     the per-response masking nonce, {@code Nn} bytes
 * @param maskedResponse   the server public key and envelope, XORed with a pad derived from the
 *                         masking key. Masking is what makes a response for an unregistered
 *                         credential indistinguishable in content from a real one — though not, on
 *                         its own, indistinguishable in timing
 */
public record CredentialResponse(byte[] evaluatedElement, byte[] maskingNonce, byte[] maskedResponse) {
}
