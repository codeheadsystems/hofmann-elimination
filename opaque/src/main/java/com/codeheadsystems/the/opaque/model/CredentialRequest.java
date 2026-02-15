package com.codeheadsystems.the.opaque.model;

/**
 * Client's credential request: { blindedElement }.
 */
public record CredentialRequest(byte[] blindedElement) {
}
