package com.codeheadsystems.opaque.model;

/**
 * Client's registration request: { blindedElement }.
 */
public record RegistrationRequest(byte[] blindedElement) {
}
