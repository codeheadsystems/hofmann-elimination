package com.codeheadsystems.the.opaque.model;

/**
 * Result of the server GenerateKE2 operation.
 *
 * @param serverAuthState server-side state needed to verify the client's final KE3 message
 * @param ke2             the KE2 message to send to the client
 */
public record ServerKE2Result(ServerAuthState serverAuthState, KE2 ke2) {
}
