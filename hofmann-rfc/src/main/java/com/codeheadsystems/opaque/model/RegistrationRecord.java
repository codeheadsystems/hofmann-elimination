package com.codeheadsystems.opaque.model;

/**
 * Server-stored registration record: { clientPublicKey, maskingKey, envelope }.
 */
public record RegistrationRecord(byte[] clientPublicKey, byte[] maskingKey, Envelope envelope) {
}
