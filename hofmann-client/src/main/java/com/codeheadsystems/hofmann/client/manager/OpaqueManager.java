package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.OpaqueAccessor;
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
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.CredentialResponse;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import java.util.Base64;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-level orchestrator for the OPAQUE-3DH protocol (RFC 9807).
 * <p>
 * Handles both the registration flow (3 steps) and the authentication flow (3 steps) by
 * coordinating the cryptographic operations (via the opaque {@link Client}) with the HTTP
 * transport layer (via {@link OpaqueAccessor}).  Callers deal only with plain passwords and
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
public class OpaqueManager {

  private static final Logger log = LoggerFactory.getLogger(OpaqueManager.class);

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  private final Client client;
  private final OpaqueAccessor accessor;

  @Inject
  public OpaqueManager(final OpaqueClientConfig config, final OpaqueAccessor accessor) {
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
        new RegistrationStartRequest(
            B64.encodeToString(credentialIdentifier),
            B64.encodeToString(regState.request().blindedElement())));

    // Step 2 — finalize locally: unbind, derive the envelope, and build the registration record
    RegistrationResponse registrationResponse = new RegistrationResponse(
        B64D.decode(startResp.evaluatedElementBase64()),
        B64D.decode(startResp.serverPublicKeyBase64()));
    RegistrationRecord record = client.finalizeRegistration(regState, registrationResponse,
        null, null);

    // Step 3 — upload the completed registration record to the server
    accessor.registrationFinish(serverId,
        new RegistrationFinishRequest(
            B64.encodeToString(credentialIdentifier),
            B64.encodeToString(record.clientPublicKey()),
            B64.encodeToString(record.maskingKey()),
            B64.encodeToString(record.envelope().envelopeNonce()),
            B64.encodeToString(record.envelope().authTag())));
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
        new AuthStartRequest(
            B64.encodeToString(credentialIdentifier),
            B64.encodeToString(authState.ke1().credentialRequest().blindedElement()),
            B64.encodeToString(authState.ke1().clientNonce()),
            B64.encodeToString(authState.ke1().clientAkePublicKey())));

    // Step 2 — reconstruct KE2 and compute KE3 (throws SecurityException on bad server MAC)
    KE2 ke2 = new KE2(
        new CredentialResponse(
            B64D.decode(startResp.evaluatedElementBase64()),
            B64D.decode(startResp.maskingNonceBase64()),
            B64D.decode(startResp.maskedResponseBase64())),
        B64D.decode(startResp.serverNonceBase64()),
        B64D.decode(startResp.serverAkePublicKeyBase64()),
        B64D.decode(startResp.serverMacBase64()));

    com.codeheadsystems.opaque.model.AuthResult authResult =
        client.generateKE3(authState, null, null, ke2);

    // Step 3 — send KE3 to the server; throws SecurityException on 401
    return accessor.authFinish(serverId,
        new AuthFinishRequest(
            startResp.sessionToken(),
            B64.encodeToString(authResult.ke3().clientMac())));
  }

  /**
   * Deletes a previously registered credential from the server.
   *
   * @param serverId             the server to delete from
   * @param credentialIdentifier raw bytes identifying the credential to remove
   */
  public void deleteRegistration(final ServerIdentifier serverId,
                                 final byte[] credentialIdentifier) {
    log.debug("deleteRegistration(serverId={})", serverId);
    accessor.registrationDelete(serverId,
        new RegistrationDeleteRequest(B64.encodeToString(credentialIdentifier)));
  }
}
