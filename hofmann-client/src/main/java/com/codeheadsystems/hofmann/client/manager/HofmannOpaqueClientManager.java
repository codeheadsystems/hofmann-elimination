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
import com.codeheadsystems.opaque.Client;
import com.codeheadsystems.opaque.model.AuthResult;
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.RegistrationRecord;
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

  private final Client client;
  private final HofmannOpaqueAccessor accessor;

  @Inject
  public HofmannOpaqueClientManager(final OpaqueClientConfig config, final HofmannOpaqueAccessor accessor) {
    log.info("OpaqueManager()");
    this.client = new Client(config.opaqueConfig());
    this.accessor = accessor;
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
    log.debug("register(serverId={})", serverId);

    // Step 1 — blind the password and obtain the OPRF-evaluated element from the server
    ClientRegistrationState regState = client.createRegistrationRequest(password);
    RegistrationStartResponse startResp = accessor.registrationStart(serverId,
        new RegistrationStartRequest(credentialIdentifier, regState.request()));

    // Step 2 — finalize locally: unblind, derive the envelope, and build the registration record
    RegistrationRecord record = client.finalizeRegistration(
        regState, startResp.registrationResponse(), null, null);

    // Step 3 — upload the completed registration record to the server
    accessor.registrationFinish(serverId,
        new RegistrationFinishRequest(credentialIdentifier, record));
  }

  /**
   * Runs the full OPAQUE authentication flow for the given credential identifier and password.
   * Returns the server's auth finish response containing both the session key and a JWT token.
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
    ClientAuthState authState = client.generateKE1(password);
    AuthStartResponse startResp = accessor.authStart(serverId,
        new AuthStartRequest(credentialIdentifier, authState.ke1()));

    // Step 2 — reconstruct KE2 and compute KE3 (throws SecurityException on bad server MAC)
    AuthResult authResult = client.generateKE3(authState, null, null, startResp.ke2());

    // Step 3 — send KE3 to the server; throws SecurityException on 401
    return accessor.authFinish(serverId,
        new AuthFinishRequest(startResp.sessionToken(), authResult.ke3()));
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
