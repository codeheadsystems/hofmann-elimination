package com.codeheadsystems.rfc.opaque.model;

/**
 * Server's registration response: { evaluatedElement, serverPublicKey }.
 *
 * @param evaluatedElement the OPRF evaluation of the client's blinded element under the server's
 *                         per-credential OPRF key, {@code Ne} bytes
 * @param serverPublicKey  the server's long-term public key, {@code Npk} bytes. The client stores
 *                         this in its envelope, so a client that accepts a substituted key here
 *                         binds its registration to the wrong server — obtain it over an
 *                         authenticated channel
 */
public record RegistrationResponse(byte[] evaluatedElement, byte[] serverPublicKey) {
}
