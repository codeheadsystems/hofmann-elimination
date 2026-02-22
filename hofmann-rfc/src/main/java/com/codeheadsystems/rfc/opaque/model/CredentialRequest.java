package com.codeheadsystems.rfc.opaque.model;

/**
 * Client's credential request: { blindedElement }.
 */
public record CredentialRequest(byte[] blindedElement) {
}
