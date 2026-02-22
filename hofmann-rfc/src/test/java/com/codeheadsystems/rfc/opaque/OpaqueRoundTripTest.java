package com.codeheadsystems.rfc.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.CredentialResponse;
import com.codeheadsystems.rfc.opaque.model.KE2;
import com.codeheadsystems.rfc.opaque.model.KE3;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import com.codeheadsystems.rfc.common.RandomProvider;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Integration tests: full registration + authentication round trips.
 */
class OpaqueRoundTripTest {

  private static final byte[] CREDENTIAL_IDENTIFIER = "user@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD_CORRECT = "correct-password".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD_WRONG = "wrong-password".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueConfig CONFIG = OpaqueConfig.forTesting(); // Identity KSF for speed

  private Client client;
  private Server server;

  /**
   * Serializes a KE2 to its full wire format for use with {@link KE2#deserialize}.
   */
  private static byte[] serializeKE2(KE2 ke2) {
    byte[] cr = ke2.serializeCredentialResponse(); // evaluatedElement || maskingNonce || maskedResponse
    byte[] sn = ke2.serverNonce();
    byte[] sp = ke2.serverAkePublicKey();
    byte[] sm = ke2.serverMac();
    byte[] out = new byte[cr.length + sn.length + sp.length + sm.length];
    int off = 0;
    System.arraycopy(cr, 0, out, off, cr.length);
    off += cr.length;
    System.arraycopy(sn, 0, out, off, sn.length);
    off += sn.length;
    System.arraycopy(sp, 0, out, off, sp.length);
    off += sp.length;
    System.arraycopy(sm, 0, out, off, sm.length);
    return out;
  }

  static Stream<OpaqueCipherSuite> allSuites() {
    return Stream.of(
        OpaqueCipherSuite.P256_SHA256,
        OpaqueCipherSuite.P384_SHA384,
        OpaqueCipherSuite.P521_SHA512
    );
  }

  @BeforeEach
  void setUp() {
    client = new Client(CONFIG);
    server = Server.generate(CONFIG);
  }

  private RegistrationRecord register(byte[] password) {
    return register(password, null, null);
  }

  // ─── Tests ────────────────────────────────────────────────────────────────

  private RegistrationRecord register(byte[] password, byte[] serverIdentity, byte[] clientIdentity) {
    ClientRegistrationState regState = client.createRegistrationRequest(password);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    return client.finalizeRegistration(regState, response, serverIdentity, clientIdentity);
  }

  private AuthResult authenticate(RegistrationRecord record, byte[] password,
                                  byte[] serverIdentity, byte[] clientIdentity) {
    ClientAuthState authState = client.generateKE1(password);
    ServerKE2Result ke2Result = server.generateKE2(serverIdentity, record, CREDENTIAL_IDENTIFIER, authState.ke1(), clientIdentity);
    KE2 ke2 = ke2Result.ke2();
    return client.generateKE3(authState, clientIdentity, serverIdentity, ke2);
  }

  @Test
  void registrationThenSuccessfulAuthentication() {
    RegistrationRecord record = register(PASSWORD_CORRECT);
    AuthResult clientResult = authenticate(record, PASSWORD_CORRECT, null, null);

    assertThat(clientResult.sessionKey()).isNotNull().hasSize(32);
    assertThat(clientResult.exportKey()).isNotNull().hasSize(32);
    assertThat(clientResult.ke3().clientMac()).isNotNull().hasSize(32);
  }

  @Test
  void serverAndClientAgreeOnSessionKey() {
    RegistrationRecord record = register(PASSWORD_CORRECT);

    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = ke2Result.ke2();
    ServerAuthState serverAuthState = ke2Result.serverAuthState();

    AuthResult clientResult = client.generateKE3(authState, null, null, ke2);
    byte[] serverSessionKey = server.serverFinish(serverAuthState, clientResult.ke3());

    assertThat(clientResult.sessionKey()).isEqualTo(serverSessionKey);
  }

  @Test
  void wrongPasswordCausesEnvelopeAuthFailure() {
    RegistrationRecord record = register(PASSWORD_CORRECT);

    assertThatThrownBy(() -> authenticate(record, PASSWORD_WRONG, null, null))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void twoRegistrationsProduceDifferentRecords() {
    RegistrationRecord record1 = register(PASSWORD_CORRECT);
    RegistrationRecord record2 = register(PASSWORD_CORRECT);

    // Different envelope nonces → different envelopes (masking key is deterministic for same password)
    assertThat(record1.envelope().envelopeNonce()).isNotEqualTo(record2.envelope().envelopeNonce());
    assertThat(record1.envelope().authTag()).isNotEqualTo(record2.envelope().authTag());
  }

  @Test
  void serverFinishWithWrongKE3Throws() {
    RegistrationRecord record = register(PASSWORD_CORRECT);

    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = ke2Result.ke2();
    ServerAuthState serverAuthState = ke2Result.serverAuthState();

    // Tamper with KE3
    KE3 tamperedKE3 = new KE3(new byte[32]); // all-zeros MAC
    assertThatThrownBy(() -> server.serverFinish(serverAuthState, tamperedKE3))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void twoConsecutiveAuthenticationsProduceDifferentSessionKeys() {
    RegistrationRecord record = register(PASSWORD_CORRECT);

    AuthResult result1 = authenticate(record, PASSWORD_CORRECT, null, null);
    AuthResult result2 = authenticate(record, PASSWORD_CORRECT, null, null);

    // Different nonces each time → different session keys
    assertThat(result1.sessionKey()).isNotEqualTo(result2.sessionKey());
  }

  @Test
  void authenticationWithExplicitIdentities() {
    byte[] serverIdentity = "server.example.com".getBytes(StandardCharsets.UTF_8);
    byte[] clientIdentity = "alice@example.com".getBytes(StandardCharsets.UTF_8);

    RegistrationRecord record = register(PASSWORD_CORRECT, serverIdentity, clientIdentity);

    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(serverIdentity, record, CREDENTIAL_IDENTIFIER,
        authState.ke1(), clientIdentity);
    KE2 ke2 = ke2Result.ke2();
    ServerAuthState serverAuthState = ke2Result.serverAuthState();

    AuthResult clientResult = client.generateKE3(authState, clientIdentity, serverIdentity, ke2);
    byte[] serverSessionKey = server.serverFinish(serverAuthState, clientResult.ke3());

    assertThat(clientResult.sessionKey()).isEqualTo(serverSessionKey);
    assertThat(clientResult.exportKey()).isNotNull().hasSize(32);
  }

  @Test
  void authenticationWithWrongIdentityFails() {
    byte[] correctServerIdentity = "server.example.com".getBytes(StandardCharsets.UTF_8);
    byte[] wrongServerIdentity = "evil.example.com".getBytes(StandardCharsets.UTF_8);
    byte[] clientIdentity = "alice@example.com".getBytes(StandardCharsets.UTF_8);

    RegistrationRecord record = register(PASSWORD_CORRECT, correctServerIdentity, clientIdentity);

    // Client registers with correctServerIdentity but authenticates with wrongServerIdentity
    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      ServerKE2Result ke2Result = server.generateKE2(wrongServerIdentity, record, CREDENTIAL_IDENTIFIER,
          authState.ke1(), clientIdentity);
      KE2 ke2 = ke2Result.ke2();
      client.generateKE3(authState, clientIdentity, wrongServerIdentity, ke2);
    }).isInstanceOf(SecurityException.class);
  }

  @Test
  void wrongClientIdentityDuringLoginFails() {
    byte[] serverIdentity = "server.example.com".getBytes(StandardCharsets.UTF_8);
    byte[] correctClientIdentity = "alice@example.com".getBytes(StandardCharsets.UTF_8);
    byte[] wrongClientIdentity = "mallory@example.com".getBytes(StandardCharsets.UTF_8);

    RegistrationRecord record = register(PASSWORD_CORRECT, serverIdentity, correctClientIdentity);

    // Server uses correct identity; client claims wrong identity in generateKE3.
    // This causes both envelope auth_tag mismatch (wrong identity in cleartext credentials)
    // and preamble mismatch (wrong identity in transcript).
    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      ServerKE2Result ke2Result = server.generateKE2(serverIdentity, record, CREDENTIAL_IDENTIFIER,
          authState.ke1(), correctClientIdentity);
      KE2 ke2 = ke2Result.ke2();
      client.generateKE3(authState, wrongClientIdentity, serverIdentity, ke2);
    }).isInstanceOf(SecurityException.class);
  }

  @Test
  void serverImpersonationFailsAuthentication() {
    // An attacker who knows the real server's public key but has a different private key
    // cannot produce a KE2 that passes client-side server MAC verification.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    byte[] realServerPublicKey = server.getServerPublicKey();

    // Impersonator presents the real server's public key (so envelope recovery succeeds)
    // but uses a different private key (so the 3DH outputs differ).
    byte[] fakePrivateKey = new RandomProvider().randomBytes(32);
    byte[] fakeOprfSeed = new RandomProvider().randomBytes(32);
    Server impersonator = new Server(fakePrivateKey, realServerPublicKey, fakeOprfSeed, CONFIG);

    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      // Impersonator must also use the real masking key from record; since it uses a fake OPRF seed
      // the OPRF evaluation differs, so the client will fail at envelope auth_tag or server MAC.
      ServerKE2Result ke2Result = impersonator.generateKE2(null, record, CREDENTIAL_IDENTIFIER,
          authState.ke1(), null);
      KE2 ke2 = ke2Result.ke2();
      client.generateKE3(authState, null, null, ke2);
    }).isInstanceOf(SecurityException.class);
  }

  @Test
  void fakeKE2CausesAuthenticationFailure() {
    // When a user has not registered, the server responds with a fake KE2.
    // The client cannot authenticate — fails at envelope auth_tag verification
    // (same point and exception as a wrong-password attempt).
    byte[] unknownCredentialId = "unknown@example.com".getBytes(StandardCharsets.UTF_8);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateFakeKE2(authState.ke1(), unknownCredentialId, null, null);
    KE2 ke2 = ke2Result.ke2();

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, ke2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void fakeKE2IsIndistinguishableFromWrongPassword() {
    // Both scenarios produce the same SecurityException at the same protocol step,
    // ensuring an attacker cannot distinguish registered from unregistered users.
    RegistrationRecord record = register(PASSWORD_CORRECT);

    // Capture wrong-password exception
    SecurityException wrongPwdEx = null;
    try {
      ClientAuthState a = client.generateKE1(PASSWORD_WRONG);
      ServerKE2Result r = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, a.ke1(), null);
      client.generateKE3(a, null, null, r.ke2());
    } catch (SecurityException e) {
      wrongPwdEx = e;
    }

    // Capture fake-user exception
    byte[] unknownCredId = "nobody@example.com".getBytes(StandardCharsets.UTF_8);
    SecurityException fakeUserEx = null;
    try {
      ClientAuthState a = client.generateKE1(PASSWORD_CORRECT);
      ServerKE2Result r = server.generateFakeKE2(a.ke1(), unknownCredId, null, null);
      client.generateKE3(a, null, null, r.ke2());
    } catch (SecurityException e) {
      fakeUserEx = e;
    }

    assertThat(wrongPwdEx).isNotNull();
    assertThat(fakeUserEx).isNotNull();
    assertThat(fakeUserEx.getMessage()).isEqualTo(wrongPwdEx.getMessage());
  }

  // ─── Additional coverage ──────────────────────────────────────────────────

  @Test
  void exportKeyIsReproducibleAcrossSessions() {
    // The export_key is derived from randomizedPwd (deterministic given correct password)
    // and the envelope nonce (fixed at registration). It must be identical on every login.
    RegistrationRecord record = register(PASSWORD_CORRECT);

    AuthResult result1 = authenticate(record, PASSWORD_CORRECT, null, null);
    AuthResult result2 = authenticate(record, PASSWORD_CORRECT, null, null);

    assertThat(result1.exportKey()).isEqualTo(result2.exportKey());
    // Session keys must still be fresh each time
    assertThat(result1.sessionKey()).isNotEqualTo(result2.sessionKey());
  }

  @Test
  void multipleIndependentUsers() {
    // Two distinct users can register and authenticate on the same server without interference.
    byte[] cred1 = "user1@example.com".getBytes(StandardCharsets.UTF_8);
    byte[] cred2 = "user2@example.com".getBytes(StandardCharsets.UTF_8);
    byte[] pwd1 = "password-for-user1".getBytes(StandardCharsets.UTF_8);
    byte[] pwd2 = "password-for-user2".getBytes(StandardCharsets.UTF_8);

    ClientRegistrationState s1 = client.createRegistrationRequest(pwd1);
    RegistrationRecord r1 = client.finalizeRegistration(s1,
        server.createRegistrationResponse(s1.request(), cred1), null, null);

    ClientRegistrationState s2 = client.createRegistrationRequest(pwd2);
    RegistrationRecord r2 = client.finalizeRegistration(s2,
        server.createRegistrationResponse(s2.request(), cred2), null, null);

    // User 1 authenticates
    ClientAuthState a1 = client.generateKE1(pwd1);
    ServerKE2Result ke2r1 = server.generateKE2(null, r1, cred1, a1.ke1(), null);
    AuthResult res1 = client.generateKE3(a1, null, null, ke2r1.ke2());
    byte[] serverKey1 = server.serverFinish(ke2r1.serverAuthState(), res1.ke3());
    assertThat(res1.sessionKey()).isEqualTo(serverKey1);

    // User 2 authenticates independently
    ClientAuthState a2 = client.generateKE1(pwd2);
    ServerKE2Result ke2r2 = server.generateKE2(null, r2, cred2, a2.ke1(), null);
    AuthResult res2 = client.generateKE3(a2, null, null, ke2r2.ke2());
    byte[] serverKey2 = server.serverFinish(ke2r2.serverAuthState(), res2.ke3());
    assertThat(res2.sessionKey()).isEqualTo(serverKey2);

    // Their session keys are independent
    assertThat(res1.sessionKey()).isNotEqualTo(res2.sessionKey());
  }

  @Test
  void argon2idKsfRoundTrip() {
    // OpaqueConfig.DEFAULT uses Argon2id but all other tests use IdentityKsf.
    // Use minimal Argon2id params (64 KB, 1 iteration) to keep the test fast
    // while still exercising the production KSF code path.
    OpaqueConfig argon2Config = OpaqueConfig.withArgon2id(
        "OPAQUE-TEST".getBytes(StandardCharsets.UTF_8), 64, 1, 1);
    Client argon2Client = new Client(argon2Config);
    Server argon2Server = Server.generate(argon2Config);

    ClientRegistrationState regState = argon2Client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = argon2Client.finalizeRegistration(regState,
        argon2Server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER),
        null, null);

    ClientAuthState authState = argon2Client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = argon2Server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = ke2Result.ke2();
    ServerAuthState serverAuthState = ke2Result.serverAuthState();

    AuthResult result = argon2Client.generateKE3(authState, null, null, ke2);
    byte[] serverKey = argon2Server.serverFinish(serverAuthState, result.ke3());
    assertThat(result.sessionKey()).isEqualTo(serverKey);
    assertThat(result.exportKey()).isNotNull().hasSize(32);

    // Wrong password must still fail under Argon2id.
    assertThatThrownBy(() -> {
      ClientAuthState bad = argon2Client.generateKE1(PASSWORD_WRONG);
      ServerKE2Result r = argon2Server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, bad.ke1(), null);
      argon2Client.generateKE3(bad, null, null, r.ke2());
    }).isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void tamperedServerMacInKE2CausesSecurityException() {
    // "Server MAC verification failed" is only reachable when the credential response
    // decrypts correctly (so the envelope auth_tag passes) but the server MAC is wrong.
    // This simulates a MITM that relays a valid credential response with a forged MAC.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 realKe2 = ke2Result.ke2();

    // Keep the real credential response so envelope recovery succeeds; tamper only the server MAC.
    KE2 tamperedKe2 = new KE2(
        realKe2.credentialResponse(),
        realKe2.serverNonce(),
        realKe2.serverAkePublicKey(),
        new byte[32]  // all-zeros — definitely wrong
    );

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, tamperedKe2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void differentContextsCauseMacMismatch() {
    // RFC §6.1: the context string must be globally unique and is bound into the preamble.
    // A client configured with a different context string cannot authenticate against a
    // server that used a different context — the preamble diverges → different km2 → server
    // MAC mismatch.  The envelope auth_tag is unaffected (context is not in the envelope).
    OpaqueConfig configA = new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
        "CONTEXT-A".getBytes(StandardCharsets.UTF_8), new OpaqueConfig.IdentityKsf(), new RandomProvider());
    OpaqueConfig configB = new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
        "CONTEXT-B".getBytes(StandardCharsets.UTF_8), new OpaqueConfig.IdentityKsf(), new RandomProvider());

    Server serverA = Server.generate(configA);
    Client clientA = new Client(configA);
    Client clientB = new Client(configB);

    ClientRegistrationState regState = clientA.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = clientA.finalizeRegistration(regState,
        serverA.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER),
        null, null);

    assertThatThrownBy(() -> {
      ClientAuthState authState = clientB.generateKE1(PASSWORD_CORRECT);
      ServerKE2Result ke2Result = serverA.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
      clientB.generateKE3(authState, null, null, ke2Result.ke2());
    }).isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void reRegistrationChangesExportKey() {
    // Each registration uses a fresh random envelope nonce, so the export_key changes.
    // Applications that store data encrypted under export_key must handle this on re-registration.
    RegistrationRecord record1 = register(PASSWORD_CORRECT);
    RegistrationRecord record2 = register(PASSWORD_CORRECT);

    AuthResult result1 = authenticate(record1, PASSWORD_CORRECT, null, null);
    AuthResult result2 = authenticate(record2, PASSWORD_CORRECT, null, null);

    assertThat(result1.exportKey()).isNotEqualTo(result2.exportKey());
    assertThat(result1.sessionKey()).isNotNull().hasSize(32);
    assertThat(result2.sessionKey()).isNotNull().hasSize(32);
  }

  @Test
  void wrongCredentialIdentifierCausesAuthFailure() {
    // If the server looks up the wrong credential identifier when evaluating the OPRF,
    // it derives a different OPRF key → different randomized_pwd → envelope auth_tag mismatch.
    byte[] aliceCredId = "alice@example.com".getBytes(StandardCharsets.UTF_8);
    byte[] bobCredId = "bob@example.com".getBytes(StandardCharsets.UTF_8);

    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = client.finalizeRegistration(regState,
        server.createRegistrationResponse(regState.request(), aliceCredId), null, null);

    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      // Server accidentally uses bob's credentialIdentifier for alice's record.
      ServerKE2Result ke2Result = server.generateKE2(null, record, bobCredId, authState.ke1(), null);
      client.generateKE3(authState, null, null, ke2Result.ke2());
    }).isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void generateProducesValidKeyPair() {
    // OpaqueServer.generate() must produce a valid compressed P-256 public key
    // and the resulting server must be immediately usable for a full protocol round trip.
    Server generated = Server.generate(CONFIG);
    byte[] pk = generated.getServerPublicKey();

    // Compressed SEC1 P-256 point: 33 bytes, first byte 0x02 or 0x03.
    assertThat(pk).hasSize(33);
    assertThat(pk[0]).isIn((byte) 0x02, (byte) 0x03);

    Client c = new Client(CONFIG);
    ClientRegistrationState regState = c.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = c.finalizeRegistration(regState,
        generated.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER),
        null, null);

    ClientAuthState authState = c.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = generated.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = ke2Result.ke2();
    ServerAuthState sas = ke2Result.serverAuthState();

    AuthResult result = c.generateKE3(authState, null, null, ke2);
    byte[] serverKey = generated.serverFinish(sas, result.ke3());
    assertThat(result.sessionKey()).isEqualTo(serverKey);
  }

  // ─── Additional tests ────────────────────────────────────────────────────

  @Test
  void differentOprfSeedsCannotCrossAuthenticate() {
    // Two servers with identical long-term AKE keys but different OPRF seeds derive different
    // per-credential OPRF keys.  A user registered against server A cannot authenticate against
    // server B: the OPRF evaluation differs → different randomized_pwd → envelope auth_tag mismatch.
    //
    // A deterministic key pair is used so the only variable between the two servers is the seed.
    OpaqueCipherSuite.AkeKeyPair kp = CONFIG.cipherSuite().deriveAkeKeyPair(new byte[32]);
    java.math.BigInteger sharedSk = kp.privateKey();
    byte[] sharedPk = kp.publicKeyBytes();
    byte[] rawSk = sharedSk.toByteArray();
    byte[] skFixed = new byte[32];
    if (rawSk.length > 32) {
      System.arraycopy(rawSk, rawSk.length - 32, skFixed, 0, 32);
    } else {
      System.arraycopy(rawSk, 0, skFixed, 32 - rawSk.length, rawSk.length);
    }

    byte[] seedA = new RandomProvider().randomBytes(32);
    byte[] seedB = new RandomProvider().randomBytes(32);
    Server serverA = new Server(skFixed, sharedPk, seedA, CONFIG);
    Server serverB = new Server(skFixed, sharedPk, seedB, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = client.finalizeRegistration(regState,
        serverA.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER), null, null);

    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      ServerKE2Result ke2Result = serverB.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
      client.generateKE3(authState, null, null, ke2Result.ke2());
    }).isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void registrationRequestsAreUnique() {
    // createRegistrationRequest() applies a random blind on each call, so two requests
    // for the same password produce different blinded elements on the wire.
    ClientRegistrationState state1 = client.createRegistrationRequest(PASSWORD_CORRECT);
    ClientRegistrationState state2 = client.createRegistrationRequest(PASSWORD_CORRECT);

    assertThat(state1.request().blindedElement())
        .isNotEqualTo(state2.request().blindedElement());
  }

  @Test
  void maskingKeyIsDeterministicForSamePassword() {
    // maskingKey = HKDF-Expand(randomized_pwd, "MaskingKey", 32) depends only on
    // the password + server OPRF seed + credential identifier, not the envelope nonce.
    // Two registrations with the same password must produce the same masking key so
    // the server can unmask the credential response on each authentication.
    RegistrationRecord record1 = register(PASSWORD_CORRECT);
    RegistrationRecord record2 = register(PASSWORD_CORRECT);

    assertThat(record1.maskingKey()).isEqualTo(record2.maskingKey());
    // Sanity check: envelopes are still fresh (different nonces each registration)
    assertThat(record1.envelope().envelopeNonce()).isNotEqualTo(record2.envelope().envelopeNonce());
  }

  @Test
  void tamperedMaskedResponseCausesAuthFailure() {
    // The maskedResponse XOR-decrypts to serverPublicKey || envelopeNonce || authTag.
    // Corrupting any byte produces wrong envelope data, causing auth_tag mismatch.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 realKe2 = ke2Result.ke2();

    // Byte 50 falls in the masked envelope-nonce region (bytes 33–64 after unmasking),
    // so it corrupts the recovered envelopeNonce without risking an invalid-point parse.
    byte[] maskedResponse = realKe2.credentialResponse().maskedResponse().clone();
    maskedResponse[50] ^= 0xFF;

    KE2 tamperedKe2 = new KE2(
        new CredentialResponse(
            realKe2.credentialResponse().evaluatedElement(),
            realKe2.credentialResponse().maskingNonce(),
            maskedResponse),
        realKe2.serverNonce(),
        realKe2.serverAkePublicKey(),
        realKe2.serverMac());

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, tamperedKe2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void tamperedEvaluatedElementCausesEnvelopeFailure() {
    // A modified OPRF evaluated element produces the wrong randomized_pwd after unblinding,
    // which produces wrong envelope keys, causing auth_tag mismatch.
    // Flipping the sign byte (0x02 ↔ 0x03) gives the negated P-256 point — still a valid
    // curve point, so no deserialization error — but yields a different compressed encoding
    // after unblinding, diverging the OPRF output from the registered value.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 realKe2 = ke2Result.ke2();

    byte[] evaluatedElement = realKe2.credentialResponse().evaluatedElement().clone();
    evaluatedElement[0] ^= 0x01; // 0x02 ↔ 0x03: negated point, valid but wrong

    KE2 tamperedKe2 = new KE2(
        new CredentialResponse(
            evaluatedElement,
            realKe2.credentialResponse().maskingNonce(),
            realKe2.credentialResponse().maskedResponse()),
        realKe2.serverNonce(),
        realKe2.serverAkePublicKey(),
        realKe2.serverMac());

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, tamperedKe2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void ke2DeserializationRoundTrip() {
    // KE2.deserialize() must reconstruct all fields from the wire format and the
    // resulting object must be immediately usable for a successful authentication.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 original = ke2Result.ke2();

    byte[] wireBytes = serializeKE2(original);
    KE2 deserialized = KE2.deserialize(CONFIG, wireBytes);

    AuthResult result = client.generateKE3(authState, null, null, deserialized);
    assertThat(result.sessionKey()).isNotNull().hasSize(32);
    assertThat(result.exportKey()).isNotNull().hasSize(32);
  }

  @Test
  void fakeKE2WithExplicitIdentitiesFailsAuthentication() {
    // User-enumeration protection must work even when explicit identities are supplied;
    // the fake response flows through the same preamble path as a real one.
    byte[] serverIdentity = "server.example.com".getBytes(StandardCharsets.UTF_8);
    byte[] clientIdentity = "alice@example.com".getBytes(StandardCharsets.UTF_8);
    byte[] unknownCredId = "unknown@example.com".getBytes(StandardCharsets.UTF_8);

    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateFakeKE2(
        authState.ke1(), unknownCredId, serverIdentity, clientIdentity);
    KE2 ke2 = ke2Result.ke2();

    assertThatThrownBy(() -> client.generateKE3(authState, clientIdentity, serverIdentity, ke2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void concurrentAuthSessionsForSameUser() {
    // Two in-flight auth sessions for the same registered record must each complete
    // successfully and independently: same export key (deterministic per registration),
    // but distinct session keys (fresh ephemeral nonces each run).
    RegistrationRecord record = register(PASSWORD_CORRECT);

    // Both KE1s generated before either KE2 is processed
    ClientAuthState authState1 = client.generateKE1(PASSWORD_CORRECT);
    ClientAuthState authState2 = client.generateKE1(PASSWORD_CORRECT);

    ServerKE2Result ke2Result1 = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState1.ke1(), null);
    ServerKE2Result ke2Result2 = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState2.ke1(), null);

    AuthResult result1 = client.generateKE3(authState1, null, null, ke2Result1.ke2());
    AuthResult result2 = client.generateKE3(authState2, null, null, ke2Result2.ke2());

    assertThat(result1.sessionKey()).isNotNull().hasSize(32);
    assertThat(result2.sessionKey()).isNotNull().hasSize(32);
    assertThat(result1.sessionKey()).isNotEqualTo(result2.sessionKey());
    assertThat(result1.exportKey()).isEqualTo(result2.exportKey());
  }

  @Test
  void exportKeyIsIndependentOfSessionKey() {
    // RFC §10.7: export_key and session_key are derived via different HKDF-ExpandLabel
    // calls with different labels and inputs; they must never be the same value.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    AuthResult result = authenticate(record, PASSWORD_CORRECT, null, null);

    assertThat(result.exportKey()).isNotNull().hasSize(32);
    assertThat(result.sessionKey()).isNotNull().hasSize(32);
    assertThat(result.exportKey()).isNotEqualTo(result.sessionKey());
  }

  @Test
  void emptyPasswordRoundTrip() {
    // The protocol imposes no minimum password length; a zero-length password must
    // complete registration and authentication without error.
    byte[] emptyPassword = new byte[0];
    RegistrationRecord record = register(emptyPassword);
    AuthResult result = authenticate(record, emptyPassword, null, null);

    assertThat(result.sessionKey()).isNotNull().hasSize(32);
    assertThat(result.exportKey()).isNotNull().hasSize(32);
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  @Test
  void serverFinishCalledTwiceReturnsSameKey() {
    // serverFinish is a stateless MAC-verification step; calling it twice with the
    // same ServerAuthState and KE3 must return the same session key both times.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    ServerAuthState serverAuthState = ke2Result.serverAuthState();
    AuthResult clientResult = client.generateKE3(authState, null, null, ke2Result.ke2());

    byte[] sessionKey1 = server.serverFinish(serverAuthState, clientResult.ke3());
    byte[] sessionKey2 = server.serverFinish(serverAuthState, clientResult.ke3());

    assertThat(sessionKey1).isEqualTo(sessionKey2);
  }

  // ─── Parameterized multi-suite round-trip tests ────────────────────────────

  @Test
  void registrationResponseContainsServerPublicKey() {
    // The server's long-term public key must be embedded in the registration response
    // so the client can include it in the envelope for later server authentication.
    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);

    assertThat(response.serverPublicKey()).isEqualTo(server.getServerPublicKey());
  }

  @ParameterizedTest(name = "fullRoundTrip_{0}")
  @MethodSource("allSuites")
  void fullRoundTripAllSuites(OpaqueCipherSuite suite) {
    OpaqueConfig cfg = OpaqueConfig.forTesting(suite);
    Server srv = Server.generate(cfg);
    Client cli = new Client(cfg);

    // Registration
    ClientRegistrationState regState = cli.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationResponse response = srv.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = cli.finalizeRegistration(regState, response, null, null);

    // Authentication
    ClientAuthState authState = cli.generateKE1(PASSWORD_CORRECT);
    ServerKE2Result ke2Result = srv.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    AuthResult clientResult = cli.generateKE3(authState, null, null, ke2Result.ke2());
    byte[] serverSessionKey = srv.serverFinish(ke2Result.serverAuthState(), clientResult.ke3());

    assertThat(clientResult.sessionKey()).isNotNull().hasSize(suite.Nh());
    assertThat(clientResult.exportKey()).isNotNull().hasSize(suite.Nh());
    assertThat(clientResult.ke3().clientMac()).isNotNull().hasSize(suite.Nm());
    assertThat(clientResult.sessionKey()).isEqualTo(serverSessionKey);
  }

  @ParameterizedTest(name = "wrongPasswordFails_{0}")
  @MethodSource("allSuites")
  void wrongPasswordFailsAllSuites(OpaqueCipherSuite suite) {
    OpaqueConfig cfg = OpaqueConfig.forTesting(suite);
    Server srv = Server.generate(cfg);
    Client cli = new Client(cfg);

    // Registration with correct password
    ClientRegistrationState regState = cli.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationResponse response = srv.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = cli.finalizeRegistration(regState, response, null, null);

    // Authentication with wrong password must fail
    ClientAuthState authState = cli.generateKE1(PASSWORD_WRONG);
    ServerKE2Result ke2Result = srv.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);

    assertThatThrownBy(() -> cli.generateKE3(authState, null, null, ke2Result.ke2()))
        .isInstanceOf(SecurityException.class);
  }
}
