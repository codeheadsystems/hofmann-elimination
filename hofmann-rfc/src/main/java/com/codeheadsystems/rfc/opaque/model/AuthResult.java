package com.codeheadsystems.rfc.opaque.model;

/**
 * Result of a successful client-side authentication: { ke3, sessionKey, exportKey }.
 */
public record AuthResult(KE3 ke3, byte[] sessionKey, byte[] exportKey) {
}
