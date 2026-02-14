package com.codeheadsystems.opaque;

import com.codeheadsystems.hofmann.curve.Curve;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.internal.OpaqueAke;
import com.codeheadsystems.opaque.internal.OpaqueCredentials;
import com.codeheadsystems.opaque.internal.OpaqueCrypto;
import com.codeheadsystems.opaque.model.Envelope;
import com.codeheadsystems.opaque.model.KE1;
import com.codeheadsystems.opaque.model.KE3;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationRequest;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import com.codeheadsystems.opaque.model.ServerAuthState;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * OPAQUE server public API. Holds the server long-term key pair and OPRF seed.
 */
public class OpaqueServer {

  private final BigInteger serverPrivateKey;
  private final byte[] serverPublicKey;
  private final byte[] oprfSeed;
  private final OpaqueConfig config;

  /**
   * Constructs an OpaqueServer with explicit key material.
   *
   * @param serverPrivateKeyBytes 32-byte big-endian P-256 private key
   * @param serverPublicKey       33-byte compressed SEC1 P-256 public key
   * @param oprfSeed              32-byte OPRF seed
   * @param config                OPAQUE configuration
   */
  public OpaqueServer(byte[] serverPrivateKeyBytes,
                      byte[] serverPublicKey,
                      byte[] oprfSeed,
                      OpaqueConfig config) {
    this.serverPrivateKey = new BigInteger(1, serverPrivateKeyBytes);
    this.serverPublicKey = serverPublicKey;
    this.oprfSeed = oprfSeed;
    this.config = config;
  }

  /**
   * Generates a new OpaqueServer with a random P-256 key pair and random OPRF seed.
   */
  public static OpaqueServer generate(OpaqueConfig config) {
    BigInteger sk = Curve.P256_CURVE.randomScalar();
    byte[] pk = Curve.P256_CURVE.g().multiply(sk).normalize().getEncoded(true);
    byte[] seed = OpaqueCrypto.randomBytes(OpaqueConfig.Nok);
    // Convert sk to 32-byte big-endian
    byte[] skBytes = sk.toByteArray();
    byte[] skFixed = new byte[32];
    if (skBytes.length > 32) {
      System.arraycopy(skBytes, skBytes.length - 32, skFixed, 0, 32);
    } else {
      System.arraycopy(skBytes, 0, skFixed, 32 - skBytes.length, skBytes.length);
    }
    return new OpaqueServer(skFixed, pk, seed, config);
  }

  /**
   * Returns the server's public key (33 bytes).
   */
  public byte[] getServerPublicKey() {
    return serverPublicKey;
  }

  // ─── Registration ─────────────────────────────────────────────────────────

  /**
   * Creates a registration response: evaluates the OPRF and returns the server's public key.
   *
   * @param request              client's registration request
   * @param credentialIdentifier unique credential identifier for this user
   * @return registration response to send to the client
   */
  public RegistrationResponse createRegistrationResponse(RegistrationRequest request,
                                                         byte[] credentialIdentifier) {
    return OpaqueCredentials.createRegistrationResponse(
        request, serverPublicKey, credentialIdentifier, oprfSeed);
  }

  // ─── Authentication ────────────────────────────────────────────────────────

  /**
   * Generates KE2: evaluates OPRF, masks credentials, performs server-side AKE.
   *
   * @param serverIdentity       server identity bytes (null = use serverPublicKey)
   * @param record               stored registration record for this user
   * @param credentialIdentifier credential identifier for this user
   * @param ke1                  client's KE1 message
   * @param clientIdentity       client identity bytes (null = use clientPublicKey from record)
   * @return [ServerAuthState, KE2]
   */
  public Object[] generateKE2(byte[] serverIdentity,
                              RegistrationRecord record,
                              byte[] credentialIdentifier,
                              KE1 ke1,
                              byte[] clientIdentity) {
    return OpaqueAke.generateKE2(
        config.context(), serverIdentity, serverPrivateKey, serverPublicKey,
        record, credentialIdentifier, oprfSeed, ke1, clientIdentity, null, null);
  }

  /**
   * Finalizes server-side authentication: verifies the client MAC and returns the session key.
   *
   * @param state state from generateKE2
   * @param ke3   client's final message
   * @return session key
   * @throws SecurityException if client MAC verification fails
   */
  public byte[] serverFinish(ServerAuthState state,
                             KE3 ke3) {
    if (!Arrays.equals(state.expectedClientMac(), ke3.clientMac())) {
      throw new SecurityException("Client MAC verification failed");
    }
    return state.sessionKey();
  }

  // ─── Fake KE2 (user enumeration protection) ───────────────────────────────

  /**
   * Generates a fake KE2 for an unregistered credential identifier.
   * Produces a response indistinguishable from a real KE2, preventing user
   * enumeration attacks. The fake record fields are derived deterministically
   * from oprfSeed so no per-user fake record storage is required.
   *
   * <p>Per RFC 9807 §7.1.2, the server SHOULD respond identically for registered
   * and unregistered users.
   *
   * @param ke1                  client's KE1 message
   * @param credentialIdentifier credential identifier for the unknown user
   * @param serverIdentity       server identity bytes (null = use serverPublicKey)
   * @param clientIdentity       client identity bytes (null = use fake clientPublicKey)
   * @return [ServerAuthState, KE2]
   */
  public Object[] generateFakeKE2(KE1 ke1,
                                  byte[] credentialIdentifier,
                                  byte[] serverIdentity,
                                  byte[] clientIdentity) {
    RegistrationRecord fakeRecord = createFakeRecord(credentialIdentifier);
    return OpaqueAke.generateKE2(
        config.context(), serverIdentity, serverPrivateKey, serverPublicKey,
        fakeRecord, credentialIdentifier, oprfSeed, ke1, clientIdentity, null, null);
  }

  /**
   * Derives a fake RegistrationRecord deterministically from oprfSeed and
   * credentialIdentifier. Independent from any real client's randomized_password.
   */
  private RegistrationRecord createFakeRecord(byte[] credentialIdentifier) {
    byte[] fakeClientSkSeed = OpaqueCrypto.hkdfExpand(
        oprfSeed,
        OpaqueCrypto.concat(credentialIdentifier, "FakeClientKey".getBytes(StandardCharsets.US_ASCII)),
        OpaqueConfig.Nsk);
    Object[] fakeKp = OpaqueCrypto.deriveAkeKeyPairFull(fakeClientSkSeed);
    byte[] fakeClientPk = (byte[]) fakeKp[1];

    byte[] fakeMaskingKey = OpaqueCrypto.hkdfExpand(
        oprfSeed,
        OpaqueCrypto.concat(credentialIdentifier, "FakeMaskingKey".getBytes(StandardCharsets.US_ASCII)),
        OpaqueConfig.Nh);

    Envelope fakeEnvelope = new Envelope(new byte[OpaqueConfig.Nn], new byte[OpaqueConfig.Nm]);
    return new RegistrationRecord(fakeClientPk, fakeMaskingKey, fakeEnvelope);
  }

  // ─── Deterministic API (for testing) ──────────────────────────────────────

  /**
   * Generates KE2 with deterministic nonces and seeds (for test vectors).
   */
  public Object[] generateKE2Deterministic(byte[] serverIdentity,
                                           RegistrationRecord record,
                                           byte[] credentialIdentifier,
                                           KE1 ke1,
                                           byte[] clientIdentity,
                                           byte[] maskingNonce,
                                           byte[] serverAkeKeySeed,
                                           byte[] serverNonce) {
    return OpaqueAke.generateKE2Deterministic(
        config.context(), serverIdentity, serverPrivateKey, serverPublicKey,
        record, credentialIdentifier, oprfSeed, ke1, clientIdentity,
        maskingNonce, serverAkeKeySeed, serverNonce);
  }

  /**
   * Generates a fake KE2 with explicit fake record fields and deterministic nonces
   * (for RFC test vector verification).
   *
   * @param ke1                  client's KE1 message
   * @param credentialIdentifier credential identifier for the unknown user
   * @param serverIdentity       server identity bytes (null = use serverPublicKey)
   * @param clientIdentity       client identity bytes (null = use fakeClientPublicKey)
   * @param fakeClientPublicKey  33-byte compressed fake client public key
   * @param fakeMaskingKey       32-byte fake masking key
   * @param maskingNonce         32-byte masking nonce
   * @param serverAkeKeySeed     32-byte server ephemeral AKE key seed
   * @param serverNonce          32-byte server nonce
   * @return [ServerAuthState, KE2]
   */
  public Object[] generateFakeKE2Deterministic(KE1 ke1,
                                                byte[] credentialIdentifier,
                                                byte[] serverIdentity,
                                                byte[] clientIdentity,
                                                byte[] fakeClientPublicKey,
                                                byte[] fakeMaskingKey,
                                                byte[] maskingNonce,
                                                byte[] serverAkeKeySeed,
                                                byte[] serverNonce) {
    Envelope fakeEnvelope = new Envelope(new byte[OpaqueConfig.Nn], new byte[OpaqueConfig.Nm]);
    RegistrationRecord fakeRecord = new RegistrationRecord(fakeClientPublicKey, fakeMaskingKey, fakeEnvelope);
    return OpaqueAke.generateKE2Deterministic(
        config.context(), serverIdentity, serverPrivateKey, serverPublicKey,
        fakeRecord, credentialIdentifier, oprfSeed, ke1, clientIdentity,
        maskingNonce, serverAkeKeySeed, serverNonce);
  }
}
