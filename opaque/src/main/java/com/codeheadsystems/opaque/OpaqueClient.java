package com.codeheadsystems.opaque;

import com.codeheadsystems.hofmann.curve.Curve;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.internal.OpaqueAke;
import com.codeheadsystems.opaque.internal.OpaqueCredentials;
import com.codeheadsystems.opaque.internal.OpaqueCrypto;
import com.codeheadsystems.opaque.internal.OpaqueOprf;
import com.codeheadsystems.opaque.model.AuthResult;
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.CredentialRequest;
import com.codeheadsystems.opaque.model.KE1;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import java.math.BigInteger;

/**
 * OPAQUE client public API. Stateless; takes OpaqueConfig at construction time.
 */
public class OpaqueClient {

  private final OpaqueConfig config;

  public OpaqueClient(OpaqueConfig config) {
    this.config = config;
  }

  // ─── Registration ─────────────────────────────────────────────────────────

  /**
   * Creates a registration request by blinding the password.
   */
  public ClientRegistrationState createRegistrationRequest(byte[] password) {
    return OpaqueCredentials.createRegistrationRequest(password, config);
  }

  /**
   * Finalizes registration given the server's response.
   *
   * @param state          state from createRegistrationRequest
   * @param response       server's registration response
   * @param serverIdentity server identity (null = use serverPublicKey)
   * @param clientIdentity client identity (null = use clientPublicKey)
   * @return registration record to send to server for storage
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
   */
  public ClientAuthState generateKE1(byte[] password) {
    BigInteger blind = Curve.P256_CURVE.randomScalar();
    byte[] blindedElement = OpaqueOprf.blind(password, blind);
    CredentialRequest credReq = new CredentialRequest(blindedElement);

    // Derive ephemeral AKE key pair from random seed
    byte[] seed = OpaqueCrypto.randomBytes(OpaqueConfig.Nsk);
    Object[] kp = OpaqueCrypto.deriveAkeKeyPairFull(seed);
    BigInteger clientAkeSk = (BigInteger) kp[0];
    byte[] clientAkePk = (byte[]) kp[1];

    byte[] clientNonce = OpaqueCrypto.randomBytes(OpaqueConfig.Nn);
    KE1 ke1 = new KE1(credReq, clientNonce, clientAkePk);
    return new ClientAuthState(blind, password, ke1, clientAkeSk);
  }

  /**
   * Generates KE3 (final client authentication message) and produces session/export keys.
   *
   * @param state          client auth state from generateKE1
   * @param clientIdentity client identity bytes (null = use clientPublicKey from record)
   * @param serverIdentity server identity bytes (null = use serverPublicKey from credential response)
   * @param ke2            server's KE2 message
   * @return AuthResult containing KE3, sessionKey, and exportKey
   * @throws SecurityException if server MAC verification fails
   */
  public AuthResult generateKE3(ClientAuthState state,
                                byte[] clientIdentity,
                                byte[] serverIdentity,
                                KE2 ke2) {
    return OpaqueAke.generateKE3(state, clientIdentity, serverIdentity, ke2,
        config.context(), config);
  }

  // ─── Deterministic API (for testing) ──────────────────────────────────────

  /**
   * Creates a registration request with a fixed blinding factor (for test vectors).
   */
  public ClientRegistrationState createRegistrationRequestDeterministic(byte[] password,
                                                                        BigInteger blind) {
    return OpaqueCredentials.createRegistrationRequestWithBlind(password, blind, config);
  }

  /**
   * Finalizes registration with a fixed envelope nonce (for test vectors).
   */
  public RegistrationRecord finalizeRegistrationDeterministic(ClientRegistrationState state,
                                                              RegistrationResponse response,
                                                              byte[] serverIdentity,
                                                              byte[] clientIdentity,
                                                              byte[] envelopeNonce) {
    return OpaqueCredentials.finalizeRegistrationWithNonce(state, response, serverIdentity, clientIdentity,
        config, envelopeNonce);
  }

  /**
   * Generates KE1 with fixed blind, client nonce, and AKE key seed (for test vectors).
   */
  public ClientAuthState generateKE1Deterministic(byte[] password,
                                                  BigInteger blind,
                                                  byte[] clientNonce,
                                                  byte[] clientAkeKeySeed) {
    byte[] blindedElement = OpaqueOprf.blind(password, blind);
    CredentialRequest credReq = new CredentialRequest(blindedElement);

    Object[] kp = OpaqueCrypto.deriveAkeKeyPairFull(clientAkeKeySeed);
    BigInteger clientAkeSk = (BigInteger) kp[0];
    byte[] clientAkePk = (byte[]) kp[1];

    KE1 ke1 = new KE1(credReq, clientNonce, clientAkePk);
    return new ClientAuthState(blind, password, ke1, clientAkeSk);
  }
}
