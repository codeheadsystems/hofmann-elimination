package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;

/**
 * Data stored for an authenticated session.
 *
 * @param credentialIdentifier base64-encoded credential identifier
 * @param sessionKey           base64-encoded session key from the 3DH handshake
 * @param issuedAt             when the session was created
 * @param expiresAt            when the session expires
 */
public record SessionData(
    String credentialIdentifier,
    String sessionKey,
    Instant issuedAt,
    Instant expiresAt) {
}
