package com.codeheadsystems.rfc.opaque;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.internal.OpaqueAke;
import com.codeheadsystems.rfc.opaque.internal.OpaqueCredentials;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.model.KE3;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationRequest;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * OPAQUE server public API. Holds the server long-term key pair and OPRF seed.
 */
public class Server {

  private final BigInteger serverPrivateKey;
  private final byte[] serverPublicKey;
  private final byte[] oprfSeed;
  private final OpaqueConfig config;

  /**
   * Constructs an OpaqueServer with explicit key material.
   *
   * @param serverPrivateKeyBytes big-endian server private key
   * @param serverPublicKey       compressed SEC1 server public key
   * @param oprfSeed              OPRF seed
   * @param config                OPAQUE configuration
   */
  public Server(byte[] serverPrivateKeyBytes,
                byte[] serverPublicKey,
                byte[] oprfSeed,
                OpaqueConfig config) {
    this.serverPrivateKey = new BigInteger(1, serverPrivateKeyBytes);
    this.serverPublicKey = serverPublicKey;
    this.oprfSeed = oprfSeed;
    this.config = config;
  }

  /**
   * Generates a new OpaqueServer with a random key pair and random OPRF seed.
   *
   * @param config the config
   * @return the server
   */
  public static Server generate(OpaqueConfig config) {
    BigInteger sk = config.cipherSuite().oprfSuite().randomScalar();
    byte[] pk = config.cipherSuite().oprfSuite().groupSpec().scalarMultiplyGenerator(sk);
    byte[] seed = config.randomProvider().randomBytes(config.Nok());

    int nsk = config.Nsk();
    byte[] skBytes = sk.toByteArray();
    byte[] skFixed = new byte[nsk];
    if (skBytes.length > nsk) {
      System.arraycopy(skBytes, skBytes.length - nsk, skFixed, 0, nsk);
    } else {
      System.arraycopy(skBytes, 0, skFixed, nsk - skBytes.length, skBytes.length);
    }
    return new Server(skFixed, pk, seed, config);
  }

  /**
   * Returns the server's public key.
   *
   * @return the byte [ ]
   */
  public byte[] getServerPublicKey() {
    return serverPublicKey;
  }

  // ─── Registration ─────────────────────────────────────────────────────────

  /**
   * Creates a registration response: evaluates the OPRF and returns the server's public key.
   *
   * @param request              the request
   * @param credentialIdentifier the credential identifier
   * @return the registration response
   */
  public RegistrationResponse createRegistrationResponse(RegistrationRequest request,
                                                         byte[] credentialIdentifier) {
    return OpaqueCredentials.createRegistrationResponse(
        config, request, serverPublicKey, credentialIdentifier, oprfSeed);
  }

  // ─── Authentication ────────────────────────────────────────────────────────

  /**
   * Generates KE2: evaluates OPRF, masks credentials, performs server-side AKE.
   *
   * @param serverIdentity       the server identity
   * @param record               the record
   * @param credentialIdentifier the credential identifier
   * @param ke1                  the ke 1
   * @param clientIdentity       the client identity
   * @return the server ke 2 result
   */
  public ServerKE2Result generateKE2(byte[] serverIdentity,
                                     RegistrationRecord record,
                                     byte[] credentialIdentifier,
                                     KE1 ke1,
                                     byte[] clientIdentity) {
    return OpaqueAke.generateKE2(
        config, serverIdentity, serverPrivateKey, serverPublicKey,
        record, credentialIdentifier, oprfSeed, ke1, clientIdentity, null, null);
  }

  /**
   * Finalizes server-side authentication: verifies the client MAC and returns the session key.
   *
   * @param state the state
   * @param ke3   the ke 3
   * @return the byte [ ]
   */
  public byte[] serverFinish(ServerAuthState state, KE3 ke3) {
    // Security: constant-time comparison prevents timing side-channel attacks on MAC verification
    if (!MessageDigest.isEqual(state.expectedClientMac(), ke3.clientMac())) {
      throw new SecurityException("Authentication failed");
    }
    return state.sessionKey();
  }

  // ─── Fake KE2 (user enumeration protection) ───────────────────────────────

  /**
   * Generates a fake KE2 for an unregistered credential identifier.
   *
   * @param ke1                  the ke 1
   * @param credentialIdentifier the credential identifier
   * @param serverIdentity       the server identity
   * @param clientIdentity       the client identity
   * @return the server ke 2 result
   */
  public ServerKE2Result generateFakeKE2(KE1 ke1,
                                         byte[] credentialIdentifier,
                                         byte[] serverIdentity,
                                         byte[] clientIdentity) {
    RegistrationRecord fakeRecord = createFakeRecord(credentialIdentifier);
    return OpaqueAke.generateKE2(
        config, serverIdentity, serverPrivateKey, serverPublicKey,
        fakeRecord, credentialIdentifier, oprfSeed, ke1, clientIdentity, null, null);
  }

  private RegistrationRecord createFakeRecord(byte[] credentialIdentifier) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] fakeClientSkSeed = suite.hkdfExpand(
        oprfSeed,
        ByteUtils.concat(credentialIdentifier, "FakeClientKey".getBytes(StandardCharsets.US_ASCII)),
        config.Nsk());
    OpaqueCipherSuite.AkeKeyPair fakeKp = suite.deriveAkeKeyPair(fakeClientSkSeed);
    byte[] fakeClientPk = fakeKp.publicKeyBytes();

    byte[] fakeMaskingKey = suite.hkdfExpand(
        oprfSeed,
        ByteUtils.concat(credentialIdentifier, "FakeMaskingKey".getBytes(StandardCharsets.US_ASCII)),
        config.Nh());

    Envelope fakeEnvelope = new Envelope(new byte[OpaqueConfig.Nn], new byte[config.Nm()]);
    return new RegistrationRecord(fakeClientPk, fakeMaskingKey, fakeEnvelope);
  }

  // ─── Deterministic API (for testing) ──────────────────────────────────────

  /**
   * Generates KE2 with deterministic nonces and seeds (for test vectors).
   *
   * @param serverIdentity       the server identity
   * @param record               the record
   * @param credentialIdentifier the credential identifier
   * @param ke1                  the ke 1
   * @param clientIdentity       the client identity
   * @param maskingNonce         the masking nonce
   * @param serverAkeKeySeed     the server ake key seed
   * @param serverNonce          the server nonce
   * @return the server ke 2 result
   */
  public ServerKE2Result generateKE2Deterministic(byte[] serverIdentity,
                                                  RegistrationRecord record,
                                                  byte[] credentialIdentifier,
                                                  KE1 ke1,
                                                  byte[] clientIdentity,
                                                  byte[] maskingNonce,
                                                  byte[] serverAkeKeySeed,
                                                  byte[] serverNonce) {
    return OpaqueAke.generateKE2Deterministic(
        config, serverIdentity, serverPrivateKey, serverPublicKey,
        record, credentialIdentifier, oprfSeed, ke1, clientIdentity,
        maskingNonce, serverAkeKeySeed, serverNonce);
  }

  /**
   * Generates a fake KE2 with explicit fake record fields and deterministic nonces.
   *
   * @param ke1                  the ke 1
   * @param credentialIdentifier the credential identifier
   * @param serverIdentity       the server identity
   * @param clientIdentity       the client identity
   * @param fakeClientPublicKey  the fake client public key
   * @param fakeMaskingKey       the fake masking key
   * @param maskingNonce         the masking nonce
   * @param serverAkeKeySeed     the server ake key seed
   * @param serverNonce          the server nonce
   * @return the server ke 2 result
   */
  public ServerKE2Result generateFakeKE2Deterministic(KE1 ke1,
                                                      byte[] credentialIdentifier,
                                                      byte[] serverIdentity,
                                                      byte[] clientIdentity,
                                                      byte[] fakeClientPublicKey,
                                                      byte[] fakeMaskingKey,
                                                      byte[] maskingNonce,
                                                      byte[] serverAkeKeySeed,
                                                      byte[] serverNonce) {
    Envelope fakeEnvelope = new Envelope(new byte[OpaqueConfig.Nn], new byte[config.Nm()]);
    RegistrationRecord fakeRecord = new RegistrationRecord(fakeClientPublicKey, fakeMaskingKey, fakeEnvelope);
    return OpaqueAke.generateKE2Deterministic(
        config, serverIdentity, serverPrivateKey, serverPublicKey,
        fakeRecord, credentialIdentifier, oprfSeed, ke1, clientIdentity,
        maskingNonce, serverAkeKeySeed, serverNonce);
  }
}
