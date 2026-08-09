package com.codeheadsystems.rfc.opaque;

import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
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
 * OPAQUE client public API.
 *
 * <p><strong>The client itself is stateless and safe to share</strong> — it holds only the
 * {@link OpaqueConfig} given at construction. The <em>state objects it returns</em> are not: each
 * carries a copy of the caller's password and must be closed.
 *
 * <p>{@link #createRegistrationRequest(byte[])}, {@link #generateKE1(byte[])} and
 * {@link #generateKE3(ClientAuthState, byte[], byte[], KE2)} all return {@link AutoCloseable}
 * values. Scope a {@code try}-with-resources to the whole exchange:
 *
 * <pre>{@code
 * try (ClientAuthState state = client.generateKE1(password)) {
 *   KE2 ke2 = server.exchange(state.ke1());
 *   try (AuthResult result = client.generateKE3(state, null, null, ke2)) {
 *     send(result.ke3());
 *   }
 * }
 * }</pre>
 *
 * <p>Closing during an exchange rather than after it is refused rather than silently mis-answered:
 * every accessor on a closed state throws
 * {@link com.codeheadsystems.rfc.common.ClosedContextException}. The caller's own password array is
 * never touched — the state copies it — so it remains yours to clear.
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
   * <p>The returned state holds a copy of the password and <strong>must be closed</strong> once
   * {@link #finalizeRegistration} has run. See {@link ClientRegistrationState} — closing it early
   * is refused, and before that guard existed it produced a registration record no password could
   * ever open.
   *
   * @param password the password; copied by the returned state, and still yours to clear
   * @return the client registration state, which the caller must close
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
   * <p>The returned state holds a copy of the password and <strong>must be closed</strong> after
   * {@link #generateKE3} has consumed it — not before, and not between the two calls. See
   * {@link ClientAuthState}.
   *
   * @param password the password; copied by the returned state, and still yours to clear
   * @return the client auth state, which the caller must close
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
   * <p>This is where a wrong password, a hostile server and a caller lifetime bug all surface, and
   * they are deliberately distinguishable — see the {@code @throws} below. The returned
   * {@link AuthResult} holds the session and export keys and <strong>must be closed</strong>; take
   * what you need from it first, because closing zeroes arrays the caller may still hold.
   *
   * @param state          the state from {@link #generateKE1}, which must not have been closed
   * @param clientIdentity the client identity, or null to use the client public key
   * @param serverIdentity the server identity, or null to use the server public key
   * @param ke2            the server's KE2 message
   * @return the auth result, which the caller must close
   * @throws SecurityException if the server MAC in KE2 does not verify. This means <em>either</em>
   *                           a wrong password <em>or</em> the wrong server — OPAQUE cannot tell
   *                           the caller which, by design, and neither can this method
   * @throws com.codeheadsystems.rfc.common.ClosedContextException if {@code state} has already been
   *                           closed. Distinct from the above on purpose: it is a lifetime bug in
   *                           the calling application, not a failed authentication, and reporting
   *                           it as a bad password is what the guard exists to stop
   * @throws IllegalArgumentException if the AKE Diffie-Hellman produces the identity element, which
   *                           a malicious server supplying an identity ephemeral key would force
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
  // *** What this does and does not close. *** For most of the time this comment has existed it
  // was not a boundary and said so: the same capabilities were public one package over in
  // com.codeheadsystems.rfc.opaque.internal — createRegistrationRequestWithBlind and
  // finalizeRegistrationWithNonce with identical bodies, and OpaqueAke.generateKE2 taking
  // maskingNonce and serverAkeKeySeed as ordinary parameters, which a name filter cannot see. A
  // reviewer reconstructed all five capabilities from another package using public API and no
  // reflection, replay included.
  //
  // That package is gone. OpaqueOprf, OpaqueCredentials, OpaqueEnvelope and OpaqueAke now live
  // here, package-private and final, so there is no second door and no bridge to keep in step
  // with this one. PackageBoundaryTest pins the whole public surface of this package by
  // signature rather than by name, so a new public method is a deliberate act with a failing
  // test attached — which is what the name filter could not give.
  //
  // The split-package route is closed too: the jar seals com/codeheadsystems/rfc/opaque/, so a
  // class compiled into this package from another jar fails to load with a sealing violation
  // rather than reaching these methods. See hofmann-rfc/build.gradle.kts.
  //
  // *** The residuals, which are inherent rather than deferred. ***
  //
  // The larger one is the injectable random source, and an earlier draft of this comment claimed
  // the opposite — that the server-side capabilities were "not reconstructable at all". They are.
  // OprfCipherSuite.Builder.withRandom and OpaqueConfig.withRandomConfig are production API, every
  // nonce and seed in the protocol is drawn through them, and a SecureRandom subclass whose
  // nextBytes writes a constant fixes the blind, the envelope nonce, the masking nonce, the server
  // AKE seed and the server nonce simultaneously — no reflection, no test-named method, from any
  // package. A reviewer replayed a complete authentication that way against this very tree, and
  // rebuilt a server's long-term key from a rigged suite RNG for good measure. That residual is
  // accepted and its reasoning is written down on OprfCipherSuite.withRandom: withRandom is how an
  // operator installs an HSM-backed source, and nothing can distinguish one from a stub.
  //
  // Which is why the argument for removing these methods was never "the capability becomes
  // unreachable". It is about what a caller reaches *by accident*. Passing a constant to a
  // parameter that asks for one is what pasting an RFC test vector into production code looks
  // like; writing a SecureRandom that ignores its output buffer is not something anyone does
  // without meaning to.
  //
  // The smaller one: a consumer can hand-build a fixed-blind KE1, because ClientAuthState's
  // canonical constructor is public (the record is returned from generateKE1) and
  // blind · H(password) is computable from GroupSpec, which this library publishes on purpose as
  // its RFC 9497 implementation. That is reimplementing the client from primitives.

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
