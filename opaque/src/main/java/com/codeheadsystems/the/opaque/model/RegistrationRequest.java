package com.codeheadsystems.the.opaque.model;

/**
 * Client's registration request: { blindedElement }.
 */
public record RegistrationRequest(byte[] blindedElement) {
}
