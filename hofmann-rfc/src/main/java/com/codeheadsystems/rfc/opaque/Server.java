package com.codeheadsystems.rfc.opaque;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
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
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OPAQUE server public API. Holds the server long-term key pair and OPRF seed.
 */
public class Server {

  private static final Logger LOG = LoggerFactory.getLogger(Server.class);

  private final BigInteger serverPrivateKey;
  private final byte[] serverPublicKey;
  private final byte[] oprfSeed;
  private final OpaqueConfig config;

  /**
   * Constructs an OpaqueServer with explicit key material.
   *
   * <p><strong>The private key is in the cipher suite's canonical scalar encoding</strong> — SEC1
   * big-endian on P-256/384/521, little-endian on ristretto255 per RFC 9496. It is decoded through
   * {@code GroupSpec.deserializeScalar} rather than as an unconditional big-endian integer.
   *
   * <p>That distinction was a real divergence, not a formality. OPAQUE used to read this as
   * big-endian on every suite, while the Rust port (curve25519-dalek {@code Scalar::to_bytes}) and
   * the TypeScript port ({@code numberToBytesLE}) both use ristretto255's native little-endian —
   * so Java disagreed with both on what a given 32-byte ristretto255 private key means. It never
   * produced a wrong answer, because all three derive the key from a seed and use it as a scalar,
   * and the byte encoding reaches no transcript or MAC: the envelope tag covers
   * {@code nonce || cleartext}, and cleartext carries the <em>public</em> key. The cross-implementation
   * vectors therefore passed for the right reason rather than by luck. The exposure was an operator
   * exporting a raw ristretto255 private key from one implementation and configuring it into
   * another, which would silently be a different key.
   *
   * @param serverPrivateKeyBytes server private key in the suite's canonical scalar encoding
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
    BigInteger sk = config.cipherSuite().oprfSuite().groupSpec()
        .deserializeScalar(serverPrivateKeyBytes);
    BigInteger n = config.cipherSuite().oprfSuite().groupSpec().groupOrder();
    // The constructor previously validated nothing at all, so a misconfigured deployment started
    // cleanly and failed later as an authentication error with no indication of the cause.
    //
    // A key congruent to 0 mod n is the one that is actively unsafe rather than merely wrong:
    // dh2 then produces the identity for every client, collapsing the AKE's contribution from the
    // long-term key. Mirrors the check the OPRF key supplier already performs.
    //
    // Keys at or above n are now refused by deserializeScalar above, where the OPRF key supplier
    // normalises them instead. The asymmetry is deliberate: the OPRF master key is configured as
    // raw random hex, and `openssl rand -hex 32` exceeds ristretto255's order about 94% of the
    // time, so refusing there would break working deployments. This key cannot be raw random
    // bytes — the caller must also supply the matching public key, checked below, so it can only
    // have come from a real key generation, which yields a scalar in [1, n-1].
    if (sk.mod(n).signum() == 0) {
      throw new IllegalArgumentException(
          "Server private key is congruent to zero mod the group order");
    }
    // A short OPRF seed warns rather than refusing. RFC 9807 §6.3 specifies Nh bytes, and
    // deployments on the SHA-384/SHA-512 suites are running with 32-byte seeds today, so refusing
    // would take them down at startup. But "the expansion accepts any length" is not why it is
    // safe, and that reasoning would license a 16-byte seed.
    //
    // The seed is the PRK to HKDF-Expand in deriveOprfKey, and the credential identifier it is
    // expanded with is public — so the entire family of per-credential OPRF keys carries at most
    // H(seed) bits of entropy, whatever the group order. At 32 bytes that is 256 bits: no
    // reduction on P-256 or ristretto255, but a cap below the group order on P-384 and P-521.
    // Unreachable either way, which is why this is a warning; visible, because the reasoning
    // stops holding somewhere below 32 bytes and an operator should be told where they stand.
    if (oprfSeed.length < config.Nh()) {
      LOG.warn("OPRF seed is {} bytes; RFC 9807 §6.3 specifies Nh = {} for this suite. Every "
              + "per-credential OPRF key derives from this seed, so their combined entropy is "
              + "bounded by its length rather than by the group order — {} bits here. That is "
              + "still far beyond reach, so this is a conformance note rather than a break, but "
              + "widen the seed to {} bytes when you can rotate.",
          oprfSeed.length, config.Nh(), oprfSeed.length * 8, config.Nh());
    }
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
    // Copied, not aliased. Mutating oprfSeed after construction changes the OPRF key for every
    // credential identifier; mutating serverPublicKey after the match check above puts a key the
    // private key does not correspond to into CleartextCredentials, the masked response and the
    // preamble — past the one check that would have caught it. Same aliasing that was fixed in the
    // VOPRF/POPRF client contexts, and more consequential here.
    this.serverPublicKey = serverPublicKey.clone();
    this.oprfSeed = oprfSeed.clone();
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

    // Canonical per-suite encoding, matching what the constructor decodes. Byte-identical to the
    // old ByteUtils.scalarToFixedBytes on the three NIST suites, and little-endian rather than
    // big-endian on ristretto255 — see the constructor's javadoc.
    byte[] skFixed = config.cipherSuite().oprfSuite().groupSpec().serializeScalar(sk);
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
   * Returns a copy of the server's public key.
   *
   * <p>A copy so a caller cannot reach in and change the key this server presents. The value is
   * public, so the copy is about integrity rather than secrecy.
   *
   * @return a copy of the compressed SEC1 server public key
   */
  public byte[] getServerPublicKey() {
    return serverPublicKey.clone();
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
   * <p><strong>The returned array is {@code state}'s own, not a copy.</strong> Copy it if it must
   * outlive the state, and do not assume the two are independent — mutating one mutates the other.
   *
   * <p><strong>{@code state} is dead after this call either way.</strong> On success it has handed
   * out its session key; on failure both of its arrays are zeroed before the exception is thrown,
   * because the pending session is removed before the MAC check and can never be presented again.
   * That is why the failure path clears them here rather than leaving it to the caller — the caller
   * gets an exception, not a handle.
   *
   * @param state the server auth state from {@code generateKE2}, retrieved from the pending session
   *              store
   * @param ke3   the client's final AKE message
   * @return the session key — the live array held by {@code state}, not a copy
   * @throws SecurityException if the client MAC does not verify. Constant-time compared, so the
   *                           failure reveals nothing about how close the guess was
   */
  public byte[] serverFinish(ServerAuthState state, KE3 ke3) {
    // Security: constant-time comparison prevents timing side-channel attacks on MAC verification
    if (!MessageDigest.isEqual(state.expectedClientMac(), ke3.clientMac())) {
      // A failed KE3 ends this handshake for good — the pending session is removed before the MAC
      // is checked, so the state can never be presented again and both values are dead from here.
      // Clearing them keeps a failed guess from leaving a usable session key behind; the caller
      // has no handle to do it, since this throws instead of returning.
      Arrays.fill(state.sessionKey(), (byte) 0);
      Arrays.fill(state.expectedClientMac(), (byte) 0);
      throw new SecurityException("Authentication failed");
    }
    return state.sessionKey();
  }

  // ─── Fake KE2 (user enumeration protection) ───────────────────────────────

  /**
   * Generates a fake KE2 for an unregistered credential identifier.
   *
   * <p><strong>Prefer {@link #generateKE2ForRecordOrFake}.</strong> Calling this only on the
   * unregistered branch is what produced the timing signal RFC 9807 §10.6 exists to remove: the
   * fake record costs two HKDF expansions and a scalar multiplication that the registered branch
   * does not pay, so an attacker learns which accounts exist by timing alone. This entry point
   * remains for callers driving the fake path deliberately — tests, and anything that already
   * knows the answer — and does no equalising work of its own.
   *
   * @param ke1                  the ke 1
   * @param credentialIdentifier the credential identifier
   * @param serverIdentity       the server identity
   * @param clientIdentity       the client identity
   * @return the server ke 2 result
   * @deprecated use {@link #generateKE2ForRecordOrFake} with a null record. Deprecating this in
   *     prose alone produced no compiler warning, so a consumer following the old shape — which
   *     the integration guide still showed — reproduced the enumeration oracle with nothing to
   *     tell them. Kept rather than removed because downstream consumers legitimately call it
   *     today.
   */
  @Deprecated(since = "3.1.0", forRemoval = true)
  public ServerKE2Result generateFakeKE2(KE1 ke1,
                                         byte[] credentialIdentifier,
                                         byte[] serverIdentity,
                                         byte[] clientIdentity) {
    RegistrationRecord fakeRecord = createFakeRecord(credentialIdentifier);
    return OpaqueAke.generateKE2(
        config, serverIdentity, serverPrivateKey, serverPublicKey,
        fakeRecord, credentialIdentifier, oprfSeed, ke1, clientIdentity, null, null);
  }

  /**
   * Generates KE2 for a stored record, or a fake one when {@code record} is null, doing the same
   * work either way.
   *
   * <p>RFC 9807 §10.6 says to answer an unknown credential with a well-formed KE2 so the response
   * does not distinguish a registered account from an unregistered one. The construction was
   * followed and the goal was not: {@link #generateFakeKE2} builds a fake record first — two
   * {@code hkdfExpand} calls plus a full {@code deriveAkeKeyPair}, which is a hash-to-scalar loop
   * and a generator scalar multiplication — and only then runs the same {@code generateKE2} the
   * registered path runs. Measured at 743.7&micro;s registered against 872.7&micro;s unregistered,
   * a 17.4% offset in a fixed direction. Content that is indistinguishable does not help when the
   * latency is not.
   *
   * <p><strong>So the fake record is built unconditionally and then discarded if unused.</strong>
   * Both branches now pay for it. The alternative — caching fake records per identifier — is
   * worse in two ways: the cache is keyed on attacker-controlled input, so it is an unbounded
   * allocation, and the first probe for each identifier is still slow, which leaves the oracle in
   * place for exactly the attacker who is enumerating rather than repeating.
   *
   * <p>The cost is roughly 130&micro;s added to every legitimate authentication, against an
   * endpoint that is already rate limited and already performs several scalar multiplications.
   * That is the trade this makes, stated so it can be disagreed with.
   *
   * <p>This equalises the work; it does not make it constant-time in the strict sense, and two
   * caveats are worth more than the parenthetical they used to get.
   *
   * <p><strong>The credential store lookup is not addressed here, and on a persistent store it
   * dominates what is.</strong> Against {@code InMemoryCredentialStore} a hit and a miss are
   * indistinguishable — measured at AUC 0.5015 at the manager level, which is also why this
   * residual survived a round of measurement: the in-memory store cannot exhibit it. Against the
   * JDBC- or Redis-backed {@code CredentialStore} the interface exists for and the documentation
   * recommends for production, a miss versus a hit is a larger and far more reliable signal than
   * the ~130&micro;s this closes.
   *
   * <p>It is addressed one layer up, where the lookup actually happens: {@code
   * HofmannOpaqueServerManager.authStart} runs the lookup and everything after it under a 25 ms
   * constant-time floor, so the store's answer time is absorbed without the store needing to be
   * constant-time itself. A caller driving this method directly, without that manager, gets the
   * protocol equalisation and nothing else — if you have built your own endpoint on top of this,
   * the floor is yours to add.
   *
   * <p>And anything else the caller does on only one branch reopens it. A single per-request log
   * statement on the unregistered path measured 31.2&micro;s against a production logback
   * configuration — a cheaper oracle than the one this method closes. See
   * {@code HofmannOpaqueServerManager.warnOnceAboutMissingKeyVersion}.
   *
   * <p>The branch is also still a branch, and the two records differ in content. It closes a
   * gross, remotely measurable offset rather than a microarchitectural one.
   *
   * @param serverIdentity       the server identity
   * @param record               the stored registration record, or null when the credential is
   *                             unregistered or cannot be authenticated under a known key version
   * @param credentialIdentifier the credential identifier
   * @param ke1                  the ke 1
   * @param clientIdentity       the client identity
   * @return the server ke 2 result
   */
  public ServerKE2Result generateKE2ForRecordOrFake(byte[] serverIdentity,
                                                    RegistrationRecord record,
                                                    byte[] credentialIdentifier,
                                                    KE1 ke1,
                                                    byte[] clientIdentity) {
    // Unconditional, and deliberately not inside a branch or a ternary the JIT could hoist away:
    // its result is used on one path and its cost is paid on both.
    RegistrationRecord fakeRecord = createFakeRecord(credentialIdentifier);
    RegistrationRecord effective = (record != null) ? record : fakeRecord;
    return OpaqueAke.generateKE2(
        config, serverIdentity, serverPrivateKey, serverPublicKey,
        effective, credentialIdentifier, oprfSeed, ke1, clientIdentity, null, null);
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
  ServerKE2Result generateKE2Deterministic(byte[] serverIdentity,
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
  ServerKE2Result generateFakeKE2Deterministic(KE1 ke1,
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
