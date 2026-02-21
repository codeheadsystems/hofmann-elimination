package com.codeheadsystems.opaque;

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
public class Client {

  private final OpaqueConfig config;

  public Client(OpaqueConfig config) {
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
    BigInteger blind = config.cipherSuite().oprfSuite().randomScalar();
    byte[] seed = OpaqueCrypto.randomBytes(config.Nsk());
    byte[] clientNonce = OpaqueCrypto.randomBytes(OpaqueConfig.Nn);
    return generateKE1Deterministic(password, blind, clientNonce, seed);
  }

  /**
   * Generates KE3 (final client authentication message) and produces session/export keys.
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
    byte[] blindedElement = OpaqueOprf.blind(config.cipherSuite(), password, blind);
    CredentialRequest credReq = new CredentialRequest(blindedElement);

    OpaqueCrypto.AkeKeyPair kp = OpaqueCrypto.deriveAkeKeyPair(config.cipherSuite(), clientAkeKeySeed);
    BigInteger clientAkeSk = kp.privateKey();
    byte[] clientAkePk = kp.publicKeyBytes();

    KE1 ke1 = new KE1(credReq, clientNonce, clientAkePk);
    return new ClientAuthState(blind, password, ke1, clientAkeSk);
  }
}
