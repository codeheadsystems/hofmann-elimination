package com.codeheadsystems.rfc.opaque.model;

/**
 * Server-side state after GenerateKE2: { expectedClientMac, sessionKey }.
 *
 * <p><strong>Both components are secrets, and both are held by reference rather than copied.</strong>
 * That is the opposite of the client-side {@code ClientAuthState}, which copies the password so its
 * lifetime is independent of the caller's. Here there is nothing to decouple — both arrays are
 * freshly derived by {@code generateKE2} and have no other owner — so the record simply retains
 * them.
 *
 * <p><strong>{@code Server.serverFinish} mutates both in place on the failure path.</strong> It
 * zeroes them before throwing, because a failed KE3 ends the handshake for good and the caller
 * receives an exception rather than a handle to clear them with. A component read out of this
 * record before that call is therefore a reference to an array that may be zeroed underneath it.
 * Read what you need at the point you need it.
 *
 * <p><strong>This lands in a {@code PendingSessionStore} between KE1 and KE3</strong> (in
 * {@code hofmann-server}, which depends on this module rather than the reverse), and that has a
 * consequence worth stating for anyone implementing one.
 * The in-memory store holds this object, so the zeroing above reaches it. A store that
 * <em>serialises</em> — Redis, JDBC — has made a copy that no zeroing can reach, and that copy holds
 * a session key for the pending-session TTL. Nothing here can fix that; it is a property of putting
 * key material in an external store, and it is the reason to keep that TTL short.
 *
 * <p>Unlike the client-side state types this is <strong>not</strong> {@link AutoCloseable} and has
 * no {@code close()}, so there is no guard against use after it has been zeroed. Tracked in
 * TODO.md — closing it properly is a policy decision about the store's three exits (normal finish,
 * expiry sweep, capacity eviction) rather than a change to this type.
 *
 * @param expectedClientMac the MAC the client must present in KE3; zeroed by
 *                          {@code Server.serverFinish} if verification fails
 * @param sessionKey        the negotiated session key, returned by {@code Server.serverFinish} on
 *                          success and zeroed by it on failure
 */
public record ServerAuthState(byte[] expectedClientMac, byte[] sessionKey) {
}
