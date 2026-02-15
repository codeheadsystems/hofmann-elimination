package com.codeheadsystems.the.opaque.model;

/**
 * Server-side state after GenerateKE2: { expectedClientMac, sessionKey }.
 */
public record ServerAuthState(byte[] expectedClientMac, byte[] sessionKey) {
}
