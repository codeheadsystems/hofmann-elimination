package com.codeheadsystems.opaque.model;

/**
 * Server's registration response: { evaluatedElement, serverPublicKey }.
 */
public record RegistrationResponse(byte[] evaluatedElement, byte[] serverPublicKey) {
}
