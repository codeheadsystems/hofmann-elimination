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
    if (config == null) {
      throw new IllegalArgumentException("OPAQUE config is required");
    }
    if (serverPrivateKeyBytes == null || serverPublicKey == null || oprfSeed == null) {
      throw new IllegalArgumentException("Server key material is required");
    }
    BigInteger sk = new BigInteger(1, serverPrivateKeyBytes);
    BigInteger n = config.cipherSuite().oprfSuite().groupSpec().groupOrder();
    // The constructor previously validated nothing at all, so a misconfigured deployment started
    // cleanly and failed later as an authentication error with no indication of the cause.
    //
    // A key congruent to 0 mod n is the one that is actively unsafe rather than merely wrong:
    // dh2 then produces the identity for every client, collapsing the AKE's contribution from the
    // long-term key. Mirrors the check the OPRF key supplier already performs. Keys at or above n
    // are normalised rather than refused, for the same reason as there — `openssl rand -hex 32`
    // exceeds ristretto255's order about 94% of the time, and scalar multiplication reduces
    // anyway, so refusing would break working deployments.
    if (sk.mod(n).signum() == 0) {
      throw new IllegalArgumentException(
          "Server private key is congruent to zero mod the group order");
    }
    // The OPRF seed's length is deliberately NOT checked. RFC 9807 §6.3 specifies Nh bytes, and
    // deployments configured on the SHA-384/SHA-512 suites are running with 32-byte seeds today —
    // the seed only ever feeds an expansion that accepts any length, so refusing here would take
    // those deployments down at startup to enforce a conformance point with no security content.
    // Recorded in TODO.md rather than fixed silently.
    //
    // The public key must be the point the private key actually derives, not merely a well-formed
    // one. A mismatched pair authenticates nothing: the client verifies the envelope against the
    // public key it recovered, then runs dh2 against a private key that does not correspond to
    // it, so every authentication fails after the password has already been proven correct.
    byte[] derived = config.cipherSuite().oprfSuite().groupSpec().scalarMultiplyGenerator(sk);
    if (!MessageDigest.isEqual(derived, serverPublicKey)) {
      throw new IllegalArgumentException(
          "Server public key does not match the private key");
    }
    this.serverPrivateKey = sk;
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
    byte[] seed = config.randomProvider().randomBytes(config.Nh());

    byte[] skFixed = ByteUtils.scalarToFixedBytes(sk, config.Nsk());
    return new Server(skFixed, pk, seed, config);
  }

  /**
   * Validates a client-uploaded registration record before it is stored.
   * <p>
   * The record arrives from an unauthenticated endpoint as four independent base64 fields, so
   * nothing about its shape can be assumed. Storing it unchecked defers the failure to
   * authentication time, where it becomes worse than a bad request: {@code createCredentialResponse}
   * XORs {@code serverPublicKey || envelope} against a fixed-width pad, so a wrong-length
   * envelope throws on the length mismatch and {@code /auth/start} answers a poisoned identifier
   * with an error while an unknown one gets a fake KE2 — an enumeration oracle.
   * <p>
   * Checks every field against the suite's fixed sizes and, for the client public key, that the
   * bytes actually decode to a valid non-identity group element rather than merely being the
   * right length.
   * <p>
   * <strong>Scope.</strong> This closes the enumeration oracle. It does <em>not</em> prevent a
   * caller from storing a record that is well-formed but cryptographically meaningless — a valid
   * point with random envelope bytes passes every check here and still leaves the identifier
   * unauthenticatable, because only the password holder can produce a record that actually
   * verifies. On an unauthenticated registration endpoint that is inherent, and the answer is
   * proof of identifier ownership at the deployment layer rather than more validation here.
   *
   * @param record the client-supplied registration record
   * @throws IllegalArgumentException if any field is null or the wrong length, and — on the
   *                                  NIST suites — if the client public key does not decode
   * @throws SecurityException        if the client public key is rejected by a suite that
   *                                  signals decode failures that way (ristretto255). Callers
   *                                  that map exceptions to HTTP statuses should normalise the
   *                                  two, since which one fires depends on the suite rather
   *                                  than on the nature of the fault
   */
  public void validateRegistrationRecord(final RegistrationRecord record) {
    if (record == null) {
      throw new IllegalArgumentException("Registration record is required");
    }
    requireLength(record.clientPublicKey(), config.Npk(), "clientPublicKey");
    requireLength(record.maskingKey(), config.Nh(), "maskingKey");
    if (record.envelope() == null) {
      throw new IllegalArgumentException("Registration record envelope is required");
    }
    requireLength(record.envelope().envelopeNonce(), OpaqueConfig.Nn, "envelopeNonce");
    requireLength(record.envelope().authTag(), config.Nm(), "authTag");
    // Length alone is not enough: the client public key is used as a Diffie-Hellman peer
    // element during authentication, so it must be a real point on the curve and not the
    // identity. Multiplying by one is the interface-level way to force a decode — GroupSpec
    // exposes no deserialize method, and scalarMultiply routes through the same validation
    // (on-curve, non-identity, canonical ristretto encoding) that the AKE relies on. The
    // result is discarded; only the decode matters.
    config.cipherSuite().oprfSuite().groupSpec()
        .scalarMultiply(java.math.BigInteger.ONE, record.clientPublicKey());
  }

  private static void requireLength(final byte[] value, final int expected, final String field) {
    if (value == null || value.length != expected) {
      throw new IllegalArgumentException(
          "Invalid " + field + ": expected " + expected + " bytes, got "
              + (value == null ? "null" : String.valueOf(value.length)));
    }
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
