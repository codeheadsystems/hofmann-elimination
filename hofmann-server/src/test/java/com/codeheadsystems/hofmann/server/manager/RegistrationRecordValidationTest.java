package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A registration record arrives from an unauthenticated endpoint as four independent base64
 * fields. Storing one unchecked defers the failure to authentication time, where
 * {@code createCredentialResponse} XORs {@code serverPublicKey || envelope} against a
 * fixed-width pad: a wrong-length envelope throws on the mismatch, so a poisoned identifier
 * answers {@code /auth/start} with an error while an unknown identifier gets a fake KE2 — an
 * enumeration oracle.
 *
 * <p>Every case runs against all four cipher suites deliberately. The default P-256 suite has
 * {@code Nh == Nm == Nn == 32}, so a confusion among those three constants is invisible there;
 * P-384, P-521 and ristretto255 separate them, and P-521 additionally separates
 * {@code Npk} (67) from {@code Nsk} (66) from {@code Nh} (64).
 */
class RegistrationRecordValidationTest {

  private static final byte[] ALICE = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery".getBytes(StandardCharsets.UTF_8);
  private static final Base64.Encoder B64 = Base64.getEncoder();

  static Stream<Arguments> suites() {
    return Stream.of(
        Arguments.of("P256_SHA256", OpaqueCipherSuite.P256_SHA256),
        Arguments.of("P384_SHA384", OpaqueCipherSuite.P384_SHA384),
        Arguments.of("P521_SHA512", OpaqueCipherSuite.P521_SHA512),
        Arguments.of("RISTRETTO255_SHA512", OpaqueCipherSuite.RISTRETTO255_SHA512));
  }

  /** Everything a single suite's fixture needs, built fresh per test. */
  private record Fixture(OpaqueConfig config, Client client, Server server,
                         InMemoryCredentialStore credentialStore, JwtManager jwtManager,
                         HofmannOpaqueServerManager manager, RegistrationRecord valid) {

    static Fixture of(OpaqueCipherSuite suite) {
      OpaqueConfig config = OpaqueConfig.forTesting(suite);
      Client client = new Client(config);
      Server server = Server.generate(config);
      InMemoryCredentialStore store = new InMemoryCredentialStore();
      JwtManager jwtManager = new JwtManager(
          "test-secret-must-be-at-least-32-bytes!".getBytes(StandardCharsets.UTF_8),
          "test-issuer", 3600, new InMemorySessionStore());
      HofmannOpaqueServerManager manager =
          new HofmannOpaqueServerManager(server, store, jwtManager);
      ClientRegistrationState state = client.createRegistrationRequest(PASSWORD);
      RegistrationRecord valid = client.finalizeRegistration(
          state, server.createRegistrationResponse(state.request(), ALICE), null, null);
      return new Fixture(config, client, server, store, jwtManager, manager, valid);
    }

    RegistrationRecord withClientPublicKey(byte[] pk) {
      return new RegistrationRecord(pk, valid.maskingKey(), valid.envelope());
    }

    RegistrationRecord withEnvelope(Envelope envelope) {
      return new RegistrationRecord(valid.clientPublicKey(), valid.maskingKey(), envelope);
    }

    /**
     * Finds an encoding of the right length that genuinely does not decode to a curve point.
     *
     * <p>Flipping bits in a compressed x-coordinate is NOT enough: roughly half of all x values
     * have a square root on the curve, so a flipped encoding is a perfectly valid point about
     * half the time and a test built on one passes or fails at random. Searching until the
     * decode actually rejects makes the case deterministic.
     */
    byte[] offCurveClientPublicKey() {
      byte[] candidate = valid.clientPublicKey().clone();
      for (int i = 1; i < 512; i++) {
        candidate[candidate.length - 1] = (byte) i;
        try {
          config.cipherSuite().oprfSuite().groupSpec()
              .scalarMultiply(java.math.BigInteger.ONE, candidate);
        } catch (RuntimeException expected) {
          return candidate;
        }
      }
      throw new IllegalStateException("no off-curve encoding found");
    }

    AuthStartRequest authStartFor(byte[] credentialId) {
      KE1 ke1 = client.generateKE1(PASSWORD).ke1();
      return new AuthStartRequest(
          B64.encodeToString(credentialId),
          B64.encodeToString(ke1.credentialRequest().blindedElement()),
          B64.encodeToString(ke1.clientNonce()),
          B64.encodeToString(ke1.clientAkePublicKey()));
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void validRecordIsAccepted(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      assertThatCode(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, f.valid()))).doesNotThrowAnyException();
      assertThat(f.credentialStore().load(ALICE)).isPresent();
    } finally {
      f.manager().shutdown();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void wrongLengthEnvelopeNonceIsRejectedAndNotStored(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      RegistrationRecord poisoned = f.withEnvelope(
          new Envelope(new byte[4], f.valid().envelope().authTag()));

      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, poisoned)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("envelopeNonce");
      assertThat(f.credentialStore().load(ALICE))
          .as("a rejected record must not be persisted")
          .isEmpty();
    } finally {
      f.manager().shutdown();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void wrongLengthMaskingKeyIsRejected(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      RegistrationRecord poisoned = new RegistrationRecord(
          f.valid().clientPublicKey(), new byte[7], f.valid().envelope());

      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, poisoned)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("maskingKey");
    } finally {
      f.manager().shutdown();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void wrongLengthAuthTagIsRejected(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      RegistrationRecord poisoned = f.withEnvelope(
          new Envelope(f.valid().envelope().envelopeNonce(), new byte[3]));

      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, poisoned)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("authTag");
    } finally {
      f.manager().shutdown();
    }
  }

  /**
   * Uses the masking key's length for the nonce. On P-256 these are both 32 so the record is
   * legitimately accepted; on the other three suites they differ and it must be refused. Pins
   * that {@code Nn} is not silently interchangeable with {@code Nh}.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void nonceSizedLikeTheMaskingKeyIsRejectedWhereTheyDiffer(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      int nh = f.config().Nh();
      if (nh == OpaqueConfig.Nn) {
        return; // indistinguishable on this suite by construction
      }
      RegistrationRecord poisoned = f.withEnvelope(
          new Envelope(new byte[nh], f.valid().envelope().authTag()));

      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, poisoned)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("envelopeNonce");
    } finally {
      f.manager().shutdown();
    }
  }

  /** P-521 separates Npk (67) from Nsk (66); a key sized for the scalar must be refused. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void clientPublicKeySizedLikeAScalarIsRejected(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      int nsk = f.config().cipherSuite().Nsk();
      if (nsk == f.config().Npk()) {
        return; // indistinguishable on this suite
      }
      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, f.withClientPublicKey(new byte[nsk]))))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("clientPublicKey");
    } finally {
      f.manager().shutdown();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void wrongLengthClientPublicKeyIsRejected(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, f.withClientPublicKey(new byte[5]))))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("clientPublicKey");
    } finally {
      f.manager().shutdown();
    }
  }

  /** Right length, but not a point on the curve — a length check alone would let this through. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void offCurveClientPublicKeyIsRejected(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, f.withClientPublicKey(f.offCurveClientPublicKey()))))
          .isInstanceOf(IllegalArgumentException.class);
      assertThat(f.credentialStore().load(ALICE)).isEmpty();
    } finally {
      f.manager().shutdown();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void identityClientPublicKeyIsRejected(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE,
              f.withClientPublicKey(new byte[f.valid().clientPublicKey().length]))))
          .isInstanceOf(IllegalArgumentException.class);
    } finally {
      f.manager().shutdown();
    }
  }

  /**
   * A bad point must report as a bad request, not as an authentication failure. Which exception
   * the crypto layer raises depends on the suite — BouncyCastle throws IllegalArgumentException
   * on the NIST curves, ristretto255 raises SecurityException — so the manager normalises them.
   * Without that, a ristretto255 deployment answers a malformed key on an unauthenticated
   * endpoint with 401, an auth challenge the caller has no credentials to satisfy.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void badPointIsReportedAsBadRequestNotAuthFailure(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, f.withClientPublicKey(f.offCurveClientPublicKey()))))
          .isInstanceOf(IllegalArgumentException.class)
          .isNotInstanceOf(SecurityException.class);
    } finally {
      f.manager().shutdown();
    }
  }

  /**
   * The point of the fix: a poisoned record used to be stored, after which {@code /auth/start}
   * behaved differently for that identifier than for an unknown one. Both must look the same,
   * because the poisoned record never lands.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("suites")
  void poisonedRecordCannotCreateAnAuthStartOracle(String name, OpaqueCipherSuite suite) {
    Fixture f = Fixture.of(suite);
    try {
      RegistrationRecord poisoned = f.withEnvelope(
          new Envelope(new byte[4], f.valid().envelope().authTag()));
      assertThatThrownBy(() -> f.manager().registrationFinish(
          new RegistrationFinishRequest(ALICE, poisoned)))
          .isInstanceOf(IllegalArgumentException.class);

      assertThatCode(() -> f.manager().authStart(f.authStartFor(ALICE)))
          .doesNotThrowAnyException();
      assertThatCode(() -> f.manager().authStart(f.authStartFor(
          "nobody@example.com".getBytes(StandardCharsets.UTF_8))))
          .doesNotThrowAnyException();
    } finally {
      f.manager().shutdown();
    }
  }

  /**
   * changePasswordFinish is the third write path to the credential store and needs the same
   * guarantee. It deletes before storing, so an unvalidated record would both break the account
   * and leave it unregistered.
   */
  @Test
  void changePasswordFinishValidatesAndDoesNotDestroyTheExistingRecord() {
    Fixture f = Fixture.of(OpaqueCipherSuite.P256_SHA256);
    try {
      f.manager().registrationFinish(new RegistrationFinishRequest(ALICE, f.valid()));
      RegistrationRecord before = f.credentialStore().load(ALICE).orElseThrow();

      String jwt = f.jwtManager().issueToken(B64.encodeToString(ALICE), B64.encodeToString(new byte[32]));
      RegistrationRecord poisoned = f.withEnvelope(
          new Envelope(new byte[4], f.valid().envelope().authTag()));

      assertThatThrownBy(() ->
          f.manager().changePasswordFinish(new RegistrationFinishRequest(ALICE, poisoned), jwt))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("envelopeNonce");

      assertThat(f.credentialStore().load(ALICE))
          .as("a rejected change-password must not delete the working registration")
          .isPresent();
      assertThat(f.credentialStore().load(ALICE).orElseThrow().clientPublicKey())
          .isEqualTo(before.clientPublicKey());
    } finally {
      f.manager().shutdown();
    }
  }
}
