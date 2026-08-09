package com.codeheadsystems.rfc.opaque.model;

/**
 * Client's credential request: { blindedElement }.
 *
 * @param blindedElement the blinded password, {@code Ne} bytes. Safe on its own; not safe beside
 *                       the blind that produced it — see {@code ClientAuthState}
 */
public record CredentialRequest(byte[] blindedElement) {
}
