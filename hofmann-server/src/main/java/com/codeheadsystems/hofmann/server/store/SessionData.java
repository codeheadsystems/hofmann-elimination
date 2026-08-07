package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;

/**
 * Data stored for an authenticated session.
 *
 * <p><strong>The OPAQUE session key is deliberately not held here.</strong> It used to be, as a
 * base64 {@code String}, and nothing ever read it back: {@code JwtManager.verify} needs only the
 * subject and the jti, and revocation needs only the credential identifier. Retaining it bought
 * nothing and cost three ways — a {@code String} cannot be zeroed, so it stayed resident for the
 * session's full lifetime at the mercy of GC and swap; this is a record, so the generated
 * {@code toString} rendered the key in full to any log line that printed a {@code SessionData};
 * and the source {@code byte[]} it was encoded from was never wiped either. The key is still
 * returned to the client in {@code AuthFinishResponse}, which is the protocol's requirement, but
 * the server no longer keeps a copy.
 *
 * @param credentialIdentifier base64-encoded credential identifier
 * @param issuedAt             when the session was created
 * @param expiresAt            when the session expires
 */
public record SessionData(
    String credentialIdentifier,
    Instant issuedAt,
    Instant expiresAt) {
}
