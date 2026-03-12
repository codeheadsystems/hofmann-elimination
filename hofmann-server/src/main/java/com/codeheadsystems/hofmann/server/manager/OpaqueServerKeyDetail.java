package com.codeheadsystems.hofmann.server.manager;

import com.codeheadsystems.rfc.opaque.Server;
import java.util.Map;

/**
 * Encapsulates the current OPAQUE server keys and any previous key versions needed
 * for authenticating credentials registered under older keys.
 * <p>
 * Modeled after {@link com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail} and
 * {@link JwtKeyDetail} — a {@code Supplier<OpaqueServerKeyDetail>} is injected into
 * {@link HofmannOpaqueServerManager} so that key material can be managed dynamically.
 * <p>
 * <strong>Why versioned keys?</strong> Every OPAQUE registration record is cryptographically
 * bound to the server's {@code oprfSeed} and {@code serverPrivateKey} that were active at
 * registration time. Authenticating a credential requires the <em>same</em> keys. Key rotation
 * therefore requires keeping old keys available until all credentials have been re-registered
 * under the new keys.
 * <p>
 * <strong>Rotation workflow:</strong>
 * <ol>
 *   <li>Generate new server key seed and OPRF seed</li>
 *   <li>Deploy: new seeds as current, old seeds as previous (version 0)</li>
 *   <li>Existing users authenticate with old keys, get {@code keyRotationRequired=true}</li>
 *   <li>Clients automatically re-register via the change-password flow</li>
 *   <li>Once all credentials are migrated, remove the old keys</li>
 * </ol>
 *
 * @param currentVersion  the version number for new registrations
 * @param currentServer   the {@link Server} instance used for new registrations and current authentication
 * @param previousServers map of version → {@link Server} for authenticating credentials registered
 *                        under older keys; may be empty when no rotation is in progress
 */
public record OpaqueServerKeyDetail(
    int currentVersion,
    Server currentServer,
    Map<Integer, Server> previousServers) {

  /**
   * Creates an OpaqueServerKeyDetail with no previous keys (no rotation).
   *
   * @param server the server
   */
  public OpaqueServerKeyDetail(Server server) {
    this(0, server, Map.of());
  }

  /**
   * Returns the Server instance for the given key version.
   *
   * @param version the key version to look up
   * @return the Server for that version, or {@code null} if not found
   */
  public Server serverForVersion(int version) {
    if (version == currentVersion) {
      return currentServer;
    }
    return previousServers.get(version);
  }
}
