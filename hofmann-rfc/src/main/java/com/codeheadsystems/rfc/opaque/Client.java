package com.codeheadsystems.rfc.opaque;

import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.internal.OpaqueAke;
import com.codeheadsystems.rfc.opaque.internal.OpaqueCredentials;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.internal.OpaqueOprf;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.CredentialRequest;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.model.KE2;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import java.math.BigInteger;

/**
 * OPAQUE client public API. Stateless; takes OpaqueConfig at construction time.
 */
public class Client {

  private final OpaqueConfig config;

  /**
   * Instantiates a new Client.
   *
   * @param config the config
   */
  public Client(OpaqueConfig config) {
    this.config = config;
  }

  // ─── Registration ─────────────────────────────────────────────────────────

  /**
   * Creates a registration request by blinding the password.
   *
   * @param password the password
   * @return the client registration state
   */
  public ClientRegistrationState createRegistrationRequest(byte[] password) {
    return OpaqueCredentials.createRegistrationRequest(password, config);
  }

  /**
   * Finalizes registration given the server's response.
   *
   * @param state          the state
   * @param response       the response
   * @param serverIdentity the server identity
   * @param clientIdentity the client identity
   * @return the registration record
   */
  public RegistrationRecord finalizeRegistration(ClientRegistrationState state,
                                                 RegistrationResponse response,
                                                 byte[] serverIdentity,
                                                 byte[] clientIdentity) {
    return OpaqueCredentials.finalizeRegistration(state, response, serverIdentity, clientIdentity, config);
  }

  // ─── Authentication ────────────────────────────────────────────────────────

  /**
   * Generates KE1 (first AKE message) by blinding the password and creating a client ephemeral key pair.
   *
   * @param password the password
   * @return the client auth state
   */
  public ClientAuthState generateKE1(byte[] password) {
    BigInteger blind = config.cipherSuite().oprfSuite().randomScalar();
    byte[] seed = config.randomProvider().randomBytes(OpaqueConfig.Nn);
    byte[] clientNonce = config.randomProvider().randomBytes(OpaqueConfig.Nn);
    return generateKE1Deterministic(password, blind, clientNonce, seed);
  }

  /**
   * Generates KE3 (final client authentication message) and produces session/export keys.
   *
   * @param state          the state
   * @param clientIdentity the client identity
   * @param serverIdentity the server identity
   * @param ke2            the ke 2
   * @return the auth result
   */
  public AuthResult generateKE3(ClientAuthState state,
                                byte[] clientIdentity,
                                byte[] serverIdentity,
                                KE2 ke2) {
    return OpaqueAke.generateKE3(state, clientIdentity, serverIdentity, ke2,
        config.context(), config);
  }

  // ─── Deterministic API (test vectors only; package-private on purpose) ─────
  //
  // These were public with nothing but a "(for testing)" javadoc between them and a production
  // caller, and every misuse is silent — the protocol keeps working and produces plausible output.
  //
  // The blind is the worst of them, which is not where an earlier version of this comment ranked
  // it. It called blind reuse "a cross-account password-equality oracle", which understates it,
  // because the realistic misuse of a deterministic API is pasting the constant out of the RFC's
  // test vectors — and then the blind is not merely fixed, it is *public*. Since
  // blindedElement = blind · H(password), an attacker who knows the blind recovers the password
  // offline from one passively observed KE1: compute blind · H(guess) and compare. No server
  // interaction, no compromise, no second account. A reviewer did exactly that against this code
  // and recovered the test password. Denying offline guessing is the whole point of OPAQUE.
  //
  // Reusing the client AKE seed is the mild one: clientAkePublicKey is wire-visible and stable
  // across logins while everything else varies, so a user's sessions become linkable.
  //
  // See Server for the server-side seeds, which are worse still.
  //
  // *** What this does and does not close. *** It removes these from the two classes a caller
  // actually types, which is worth doing — but it is not a boundary. The same capabilities remain
  // public in com.codeheadsystems.rfc.opaque.internal: OpaqueCredentials.createRegistrationRequest-
  // WithBlind and finalizeRegistrationWithNonce are public static with identical bodies, and
  // OpaqueAke.generateKE2 takes maskingNonce and serverAkeKeySeed as ordinary parameters. A
  // reviewer reconstructed every one of these five capabilities from outside the package using
  // public API and no reflection. Closing it properly needs a module-info that does not export
  // the internal package; recorded in TODO.md rather than claimed here.

  /**
   * Creates a registration request with a fixed blinding factor (for test vectors).
   *
   * @param password the password
   * @param blind    the blind
   * @return the client registration state
   */
  ClientRegistrationState createRegistrationRequestDeterministic(byte[] password,
                                                                 BigInteger blind) {
    return OpaqueCredentials.createRegistrationRequestWithBlind(password, blind, config);
  }

  /**
   * Finalizes registration with a fixed envelope nonce (for test vectors).
   *
   * @param state          the state
   * @param response       the response
   * @param serverIdentity the server identity
   * @param clientIdentity the client identity
   * @param envelopeNonce  the envelope nonce
   * @return the registration record
   */
  RegistrationRecord finalizeRegistrationDeterministic(ClientRegistrationState state,
                                                       RegistrationResponse response,
                                                       byte[] serverIdentity,
                                                       byte[] clientIdentity,
                                                       byte[] envelopeNonce) {
    return OpaqueCredentials.finalizeRegistrationWithNonce(state, response, serverIdentity, clientIdentity,
        config, envelopeNonce);
  }

  /**
   * Generates KE1 with fixed blind, client nonce, and AKE key seed (for test vectors).
   *
   * @param password         the password
   * @param blind            the blind
   * @param clientNonce      the client nonce
   * @param clientAkeKeySeed the client ake key seed
   * @return the client auth state
   */
  ClientAuthState generateKE1Deterministic(byte[] password,
                                           BigInteger blind,
                                           byte[] clientNonce,
                                           byte[] clientAkeKeySeed) {
    byte[] blindedElement = OpaqueOprf.blind(config.cipherSuite(), password, blind);
    CredentialRequest credReq = new CredentialRequest(blindedElement);

    OpaqueCipherSuite.AkeKeyPair kp = config.cipherSuite().deriveAkeKeyPair(clientAkeKeySeed);
    BigInteger clientAkeSk = kp.privateKey();
    byte[] clientAkePk = kp.publicKeyBytes();

    KE1 ke1 = new KE1(credReq, clientNonce, clientAkePk);
    return new ClientAuthState(blind, password, ke1, clientAkeSk);
  }
}
