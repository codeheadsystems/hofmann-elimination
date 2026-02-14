package com.codeheadsystems.opaque.model;

/**
 * Server's credential response: { evaluatedElement, maskingNonce, maskedResponse }.
 */
public record CredentialResponse(byte[] evaluatedElement, byte[] maskingNonce, byte[] maskedResponse) {
}
