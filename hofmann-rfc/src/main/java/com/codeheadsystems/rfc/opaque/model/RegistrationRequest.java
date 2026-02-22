package com.codeheadsystems.rfc.opaque.model;

/**
 * Client's registration request: { blindedElement }.
 */
public record RegistrationRequest(byte[] blindedElement) {
}
