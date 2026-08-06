package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-level orchestrator for the OPAQUE-3DH protocol (RFC 9807).
 * <p>
 * Handles both the registration flow (3 steps) and the authentication flow (3 steps) by
 * coordinating the cryptographic operations (via the opaque {@link Client}) with the HTTP
 * transport layer (via {@link HofmannOpaqueAccessor}).  Callers deal only with plain passwords and
 * credential identifiers; all protocol details are hidden inside this class.
 * <p>
 * The OPAQUE {@link Client} is created lazily on first use per {@link ServerIdentifier}: the
 * manager auto-fetches the server's config from GET /opaque/config and caches the result.
 * <p>
 * <strong>Registration:</strong>
 * <ol>
 *   <li>Client blinds the password and sends the blinded element to the server.</li>
 *   <li>Server evaluates the OPRF and returns the evaluated element + its public key.</li>
 *   <li>Client finalizes: unblinds, derives the envelope, and uploads the registration record.</li>
 * </ol>
 * <strong>Authentication:</strong>
 * <ol>
 *   <li>Client generates KE1 (blinded element + ephemeral AKE key + nonce) and sends it.</li>
 *   <li>Server evaluates OPRF, decrypts the envelope, and returns KE2 (+ session token).</li>
 *   <li>Client verifies the server MAC, computes KE3, sends it, and receives the session key.</li>
 * </ol>
 */
@Singleton
public class HofmannOpaqueClientManager {

  private static final Logger log = LoggerFactory.getLogger(HofmannOpaqueClientManager.class);

  private final HofmannOpaqueAccessor accessor;
  private final Map<ServerIdentifier, OpaqueClientConfig> overrides;
  private final ConcurrentHashMap<ServerIdentifier, Client> clientCache;
  private final boolean allowWeakServerKsf;
  private final String expectedContext;

  /**
   * Production constructor — auto-fetches OPAQUE config from each server on first use.
   *
   * @param accessor the accessor
   */
  @Inject
  public HofmannOpaqueClientManager(final HofmannOpaqueAccessor accessor) {
    this(accessor, Collections.emptyMap());
  }

  /**
   * CLI / override constructor — uses the supplied per-server config overrides; falls back to
   * auto-fetching for servers not present in the map.
   *
   * @param accessor  the accessor
   * @param overrides per-server config overrides (may be empty)
   */
  public HofmannOpaqueClientManager(final HofmannOpaqueAccessor accessor,
                                     final Map<ServerIdentifier, OpaqueClientConfig> overrides) {
    this(accessor, overrides, false);
  }

  /**
   * Constructor that additionally allows accepting weak or absent server-supplied key
   * stretching.
   * <p>
   * Pass {@code true} for {@code allowWeakServerKsf} only against a server deliberately
   * configured with {@code allowIdentityKsf} — typically tests and local development. It
   * disables the client's only check on parameters that decide offline attack cost, so it must
   * be a local decision rather than something the server can induce. See
   * {@link OpaqueClientConfig#fromServerConfig(com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse,
   * boolean)}.
   *
   * @param accessor           the accessor
   * @param overrides          per-server config overrides (may be empty)
   * @param allowWeakServerKsf true to accept the identity KSF and below-floor parameters
   */
  public HofmannOpaqueClientManager(final HofmannOpaqueAccessor accessor,
                                     final Map<ServerIdentifier, OpaqueClientConfig> overrides,
                                     final boolean allowWeakServerKsf) {
    this(accessor, overrides, allowWeakServerKsf, null);
  }

  /**
   * Constructor that additionally pins the OPAQUE context.
   * <p>
   * The context is the binding that stops a transcript from one deployment being replayed against
   * another, and USAGE.md specifies it is shared out-of-band — but it arrives from
   * {@code GET /opaque/config}, the channel an attacker in the middle controls. That matters here
   * in particular because this manager passes null for both identities, leaving the context the
   * only deployment-distinguishing value in the preamble. Supply the expected value to have the
   * server's verified against it instead of adopted.
   *
   * @param accessor           the accessor
   * @param overrides          per-server config overrides (may be empty)
   * @param allowWeakServerKsf true to accept the identity KSF and below-floor parameters
   * @param expectedContext    the locally configured context, or null to accept the server's
   */
  public HofmannOpaqueClientManager(final HofmannOpaqueAccessor accessor,
                                     final Map<ServerIdentifier, OpaqueClientConfig> overrides,
                                     final boolean allowWeakServerKsf,
                                     final String expectedContext) {
    log.info("OpaqueManager(overrides={}, allowWeakServerKsf={})",
        overrides.size(), allowWeakServerKsf);
    if (allowWeakServerKsf) {
      log.warn("allowWeakServerKsf is enabled: this client will accept password-stretching "
          + "parameters from the server without enforcing a minimum, including the identity "
          + "KSF. Do not use this in production.");
    }
    this.accessor = accessor;
    this.overrides = overrides;
    this.allowWeakServerKsf = allowWeakServerKsf;
    this.expectedContext = expectedContext;
    this.clientCache = new ConcurrentHashMap<>();
  }

  private Client clientFor(final ServerIdentifier serverId) {
    return clientCache.computeIfAbsent(serverId, id -> {
      OpaqueClientConfig cfg = overrides.get(id);
      if (cfg == null) {
        cfg = OpaqueClientConfig.fromServerConfig(
            accessor.getOpaqueConfig(id), allowWeakServerKsf, expectedContext);
      }
      return new Client(cfg.opaqueConfig());
    });
  }

  /**
   * Runs the full OPAQUE registration flow for the given credential identifier and password.
   * On success the server has stored the registration record and the method returns normally.
   *
   * @param serverId             the server to register with
   * @param credentialIdentifier raw bytes identifying the credential (e.g. UTF-8 email)
   * @param password             the password to register
   */
  public void register(final ServerIdentifier serverId,
                       final byte[] credentialIdentifier,
                       final byte[] password) {
    register(serverId, credentialIdentifier, password, null);
  }

  /**
   * Runs the full OPAQUE registration flow, optionally authorized by a recovery token.
   * <p>
   * When {@code recoveryToken} is non-null, the registration endpoints receive an
   * {@code Authorization: Bearer <recoveryToken>} header, which authorizes re-registration
   * for an existing credential (the old record is replaced and all sessions revoked).
   *
   * @param serverId             the server to register with
   * @param credentialIdentifier raw bytes identifying the credential (e.g. UTF-8 email)
   * @param password             the password to register
   * @param recoveryToken        optional recovery token (without "Bearer " prefix)
   */
  public void register(final ServerIdentifier serverId,
                       final byte[] credentialIdentifier,
                       final byte[] password,
                       final String recoveryToken) {
    log.debug("register(serverId={}, recovery={})", serverId, recoveryToken != null);

    // Step 1 — blind the password and obtain the OPRF-evaluated element from the server
    ClientRegistrationState regState = clientFor(serverId).createRegistrationRequest(password);
    RegistrationStartResponse startResp = accessor.registrationStart(serverId,
        new RegistrationStartRequest(credentialIdentifier, regState.request()), recoveryToken);

    // Step 2 — finalize locally: unblind, derive the envelope, and build the registration record
    RegistrationRecord record = clientFor(serverId).finalizeRegistration(
        regState, startResp.registrationResponse(), null, null);

    // Step 3 — upload the completed registration record to the server
    accessor.registrationFinish(serverId,
        new RegistrationFinishRequest(credentialIdentifier, record), recoveryToken);
  }

  /**
   * Runs the full OPAQUE authentication flow for the given credential identifier and password.
   * Returns the server's auth finish response containing both the session key and a JWT token.
   * <p>
   * If the server indicates that key rotation is required (the credential was registered under
   * an older server key version), this method automatically re-registers the credential via
   * the change-password flow using the same password, so the migration is transparent to the caller.
   *
   * @param serverId             the server to authenticate against
   * @param credentialIdentifier raw bytes identifying the credential (e.g. UTF-8 email)
   * @param password             the password to authenticate with
   * @return the server's response containing session key and JWT token
   * @throws SecurityException if the server MAC in KE2 fails verification (wrong password or
   *                           server mismatch), or if the server rejects the client MAC in KE3
   */
  public AuthFinishResponse authenticate(final ServerIdentifier serverId,
                                         final byte[] credentialIdentifier,
                                         final byte[] password) {
    log.debug("authenticate(serverId={})", serverId);

    // Step 1 — generate KE1 and send it to the server
    ClientAuthState authState = clientFor(serverId).generateKE1(password);
    AuthStartResponse startResp = accessor.authStart(serverId,
        new AuthStartRequest(credentialIdentifier, authState.ke1()));

    // Step 2 — reconstruct KE2 and compute KE3 (throws SecurityException on bad server MAC)
    AuthResult authResult = clientFor(serverId).generateKE3(authState, null, null, startResp.ke2());

    // Step 3 — send KE3 to the server; throws SecurityException on 401
    AuthFinishResponse response = accessor.authFinish(serverId,
        new AuthFinishRequest(startResp.sessionToken(), authResult.ke3()));

    // Step 4 — if key rotation required, silently re-register with the same password
    if (Boolean.TRUE.equals(response.keyRotationRequired())) {
      log.info("Key rotation required for credential — re-registering under current server keys");
      changePassword(serverId, credentialIdentifier, password, response.token());
    }

    return response;
  }

  /**
   * Changes the password for an existing credential. Requires a valid JWT
   * from a prior {@link #authenticate} call.
   * <p>
   * Internally this runs the same three-step registration flow as {@link #register}, but
   * targets the dedicated password-change endpoints and passes the JWT for authorization.
   * On success the server atomically replaces the old registration record and revokes all
   * existing sessions — the user must re-authenticate with the new password.
   *
   * @param serverId             the server
   * @param credentialIdentifier credential identifier (must match JWT subject)
   * @param newPassword          the new password
   * @param bearerToken          JWT from prior authentication with old password
   */
  public void changePassword(final ServerIdentifier serverId,
                              final byte[] credentialIdentifier,
                              final byte[] newPassword,
                              final String bearerToken) {
    log.debug("changePassword(serverId={})", serverId);

    // Step 1 — blind the new password and obtain the OPRF-evaluated element from the server
    ClientRegistrationState regState = clientFor(serverId).createRegistrationRequest(newPassword);
    RegistrationStartResponse startResp = accessor.changePasswordStart(serverId,
        new RegistrationStartRequest(credentialIdentifier, regState.request()), bearerToken);

    // Step 2 — finalize locally: unblind, derive the envelope, and build the registration record
    RegistrationRecord record = clientFor(serverId).finalizeRegistration(
        regState, startResp.registrationResponse(), null, null);

    // Step 3 — upload the new registration record to the server
    accessor.changePasswordFinish(serverId,
        new RegistrationFinishRequest(credentialIdentifier, record), bearerToken);
  }

  /**
   * Deletes a previously registered credential from the server.
   * Requires a valid JWT bearer token obtained from a prior {@link #authenticate} call
   * for the same credential identifier.
   *
   * @param serverId             the server to delete from
   * @param credentialIdentifier raw bytes identifying the credential to remove
   * @param bearerToken          JWT bearer token (without "Bearer " prefix) for authentication
   */
  public void deleteRegistration(final ServerIdentifier serverId,
                                 final byte[] credentialIdentifier,
                                 final String bearerToken) {
    log.debug("deleteRegistration(serverId={})", serverId);
    accessor.registrationDelete(serverId,
        new RegistrationDeleteRequest(credentialIdentifier), bearerToken);
  }
}
