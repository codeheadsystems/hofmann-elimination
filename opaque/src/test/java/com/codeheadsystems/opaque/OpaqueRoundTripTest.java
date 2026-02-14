package com.codeheadsystems.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.model.AuthResult;
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.KE3;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import com.codeheadsystems.opaque.model.ServerAuthState;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Integration tests: full registration + authentication round trips.
 */
class OpaqueRoundTripTest {

  private static final byte[] CREDENTIAL_IDENTIFIER = "user@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD_CORRECT = "correct-password".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD_WRONG = "wrong-password".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueConfig CONFIG = OpaqueConfig.forTesting(); // Identity KSF for speed

  private OpaqueClient client;
  private OpaqueServer server;

  @BeforeEach
  void setUp() {
    client = new OpaqueClient(CONFIG);
    server = OpaqueServer.generate(CONFIG);
  }

  private RegistrationRecord register(byte[] password) {
    return register(password, null, null);
  }

  private RegistrationRecord register(byte[] password, byte[] serverIdentity, byte[] clientIdentity) {
    ClientRegistrationState regState = client.createRegistrationRequest(password);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    return client.finalizeRegistration(regState, response, serverIdentity, clientIdentity);
  }

  private AuthResult authenticate(RegistrationRecord record, byte[] password,
                                  byte[] serverIdentity, byte[] clientIdentity) {
    ClientAuthState authState = client.generateKE1(password);
    Object[] ke2Result = server.generateKE2(serverIdentity, record, CREDENTIAL_IDENTIFIER, authState.ke1(), clientIdentity);
    KE2 ke2 = (KE2) ke2Result[1];
    return client.generateKE3(authState, clientIdentity, serverIdentity, ke2);
  }

  // ─── Tests ────────────────────────────────────────────────────────────────

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
    Object[] ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = (KE2) ke2Result[1];
    ServerAuthState serverAuthState = (ServerAuthState) ke2Result[0];

    AuthResult clientResult = client.generateKE3(authState, null, null, ke2);
    byte[] serverSessionKey = server.serverFinish(serverAuthState, clientResult.ke3());

    assertThat(clientResult.sessionKey()).isEqualTo(serverSessionKey);
  }

  @Test
  void wrongPasswordCausesEnvelopeAuthFailure() {
    RegistrationRecord record = register(PASSWORD_CORRECT);

    assertThatThrownBy(() -> authenticate(record, PASSWORD_WRONG, null, null))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("auth_tag mismatch");
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
    Object[] ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = (KE2) ke2Result[1];
    ServerAuthState serverAuthState = (ServerAuthState) ke2Result[0];

    // Tamper with KE3
    KE3 tamperedKE3 = new KE3(new byte[32]); // all-zeros MAC
    assertThatThrownBy(() -> server.serverFinish(serverAuthState, tamperedKE3))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Client MAC verification failed");
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
    Object[] ke2Result = server.generateKE2(serverIdentity, record, CREDENTIAL_IDENTIFIER,
        authState.ke1(), clientIdentity);
    KE2 ke2 = (KE2) ke2Result[1];
    ServerAuthState serverAuthState = (ServerAuthState) ke2Result[0];

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
      Object[] ke2Result = server.generateKE2(wrongServerIdentity, record, CREDENTIAL_IDENTIFIER,
          authState.ke1(), clientIdentity);
      KE2 ke2 = (KE2) ke2Result[1];
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
      Object[] ke2Result = server.generateKE2(serverIdentity, record, CREDENTIAL_IDENTIFIER,
          authState.ke1(), correctClientIdentity);
      KE2 ke2 = (KE2) ke2Result[1];
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
    byte[] fakePrivateKey = com.codeheadsystems.opaque.internal.OpaqueCrypto.randomBytes(32);
    byte[] fakeOprfSeed = com.codeheadsystems.opaque.internal.OpaqueCrypto.randomBytes(32);
    OpaqueServer impersonator = new OpaqueServer(fakePrivateKey, realServerPublicKey, fakeOprfSeed, CONFIG);

    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      // Impersonator must also use the real masking key from record; since it uses a fake OPRF seed
      // the OPRF evaluation differs, so the client will fail at envelope auth_tag or server MAC.
      Object[] ke2Result = impersonator.generateKE2(null, record, CREDENTIAL_IDENTIFIER,
          authState.ke1(), null);
      KE2 ke2 = (KE2) ke2Result[1];
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
    Object[] ke2Result = server.generateFakeKE2(authState.ke1(), unknownCredentialId, null, null);
    KE2 ke2 = (KE2) ke2Result[1];

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, ke2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("auth_tag mismatch");
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
      Object[] r = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, a.ke1(), null);
      client.generateKE3(a, null, null, (KE2) r[1]);
    } catch (SecurityException e) {
      wrongPwdEx = e;
    }

    // Capture fake-user exception
    byte[] unknownCredId = "nobody@example.com".getBytes(StandardCharsets.UTF_8);
    SecurityException fakeUserEx = null;
    try {
      ClientAuthState a = client.generateKE1(PASSWORD_CORRECT);
      Object[] r = server.generateFakeKE2(a.ke1(), unknownCredId, null, null);
      client.generateKE3(a, null, null, (KE2) r[1]);
    } catch (SecurityException e) {
      fakeUserEx = e;
    }

    assertThat(wrongPwdEx).isNotNull();
    assertThat(fakeUserEx).isNotNull();
    assertThat(fakeUserEx.getMessage()).isEqualTo(wrongPwdEx.getMessage());
  }

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
    Object[] ke2r1 = server.generateKE2(null, r1, cred1, a1.ke1(), null);
    AuthResult res1 = client.generateKE3(a1, null, null, (KE2) ke2r1[1]);
    byte[] serverKey1 = server.serverFinish((ServerAuthState) ke2r1[0], res1.ke3());
    assertThat(res1.sessionKey()).isEqualTo(serverKey1);

    // User 2 authenticates independently
    ClientAuthState a2 = client.generateKE1(pwd2);
    Object[] ke2r2 = server.generateKE2(null, r2, cred2, a2.ke1(), null);
    AuthResult res2 = client.generateKE3(a2, null, null, (KE2) ke2r2[1]);
    byte[] serverKey2 = server.serverFinish((ServerAuthState) ke2r2[0], res2.ke3());
    assertThat(res2.sessionKey()).isEqualTo(serverKey2);

    // Their session keys are independent
    assertThat(res1.sessionKey()).isNotEqualTo(res2.sessionKey());
  }

  // ─── Additional coverage ──────────────────────────────────────────────────

  @Test
  void argon2idKsfRoundTrip() {
    // OpaqueConfig.DEFAULT uses Argon2id but all other tests use IdentityKsf.
    // Use minimal Argon2id params (64 KB, 1 iteration) to keep the test fast
    // while still exercising the production KSF code path.
    OpaqueConfig argon2Config = OpaqueConfig.withArgon2id(
        "OPAQUE-TEST".getBytes(StandardCharsets.UTF_8), 64, 1, 1);
    OpaqueClient argon2Client = new OpaqueClient(argon2Config);
    OpaqueServer argon2Server = OpaqueServer.generate(argon2Config);

    ClientRegistrationState regState = argon2Client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = argon2Client.finalizeRegistration(regState,
        argon2Server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER),
        null, null);

    ClientAuthState authState = argon2Client.generateKE1(PASSWORD_CORRECT);
    Object[] ke2Result = argon2Server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = (KE2) ke2Result[1];
    ServerAuthState serverAuthState = (ServerAuthState) ke2Result[0];

    AuthResult result = argon2Client.generateKE3(authState, null, null, ke2);
    byte[] serverKey = argon2Server.serverFinish(serverAuthState, result.ke3());
    assertThat(result.sessionKey()).isEqualTo(serverKey);
    assertThat(result.exportKey()).isNotNull().hasSize(32);

    // Wrong password must still fail under Argon2id.
    assertThatThrownBy(() -> {
      ClientAuthState bad = argon2Client.generateKE1(PASSWORD_WRONG);
      Object[] r = argon2Server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, bad.ke1(), null);
      argon2Client.generateKE3(bad, null, null, (KE2) r[1]);
    }).isInstanceOf(SecurityException.class)
      .hasMessageContaining("auth_tag mismatch");
  }

  @Test
  void tamperedServerMacInKE2CausesSecurityException() {
    // "Server MAC verification failed" is only reachable when the credential response
    // decrypts correctly (so the envelope auth_tag passes) but the server MAC is wrong.
    // This simulates a MITM that relays a valid credential response with a forged MAC.
    RegistrationRecord record = register(PASSWORD_CORRECT);
    ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
    Object[] ke2Result = server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 realKe2 = (KE2) ke2Result[1];

    // Keep the real credential response so envelope recovery succeeds; tamper only the server MAC.
    KE2 tamperedKe2 = new KE2(
        realKe2.credentialResponse(),
        realKe2.serverNonce(),
        realKe2.serverAkePublicKey(),
        new byte[32]  // all-zeros — definitely wrong
    );

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, tamperedKe2))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Server MAC verification failed");
  }

  @Test
  void differentContextsCauseMacMismatch() {
    // RFC §6.1: the context string must be globally unique and is bound into the preamble.
    // A client configured with a different context string cannot authenticate against a
    // server that used a different context — the preamble diverges → different km2 → server
    // MAC mismatch.  The envelope auth_tag is unaffected (context is not in the envelope).
    OpaqueConfig configA = new OpaqueConfig(0, 0, 0,
        "CONTEXT-A".getBytes(StandardCharsets.UTF_8), new OpaqueConfig.IdentityKsf());
    OpaqueConfig configB = new OpaqueConfig(0, 0, 0,
        "CONTEXT-B".getBytes(StandardCharsets.UTF_8), new OpaqueConfig.IdentityKsf());

    OpaqueServer serverA = OpaqueServer.generate(configA);
    OpaqueClient clientA = new OpaqueClient(configA);
    OpaqueClient clientB = new OpaqueClient(configB);

    ClientRegistrationState regState = clientA.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = clientA.finalizeRegistration(regState,
        serverA.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER),
        null, null);

    assertThatThrownBy(() -> {
      ClientAuthState authState = clientB.generateKE1(PASSWORD_CORRECT);
      Object[] ke2Result = serverA.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
      clientB.generateKE3(authState, null, null, (KE2) ke2Result[1]);
    }).isInstanceOf(SecurityException.class)
      .hasMessageContaining("Server MAC verification failed");
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
    byte[] bobCredId   = "bob@example.com".getBytes(StandardCharsets.UTF_8);

    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = client.finalizeRegistration(regState,
        server.createRegistrationResponse(regState.request(), aliceCredId), null, null);

    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      // Server accidentally uses bob's credentialIdentifier for alice's record.
      Object[] ke2Result = server.generateKE2(null, record, bobCredId, authState.ke1(), null);
      client.generateKE3(authState, null, null, (KE2) ke2Result[1]);
    }).isInstanceOf(SecurityException.class)
      .hasMessageContaining("auth_tag mismatch");
  }

  @Test
  void generateProducesValidKeyPair() {
    // OpaqueServer.generate() must produce a valid compressed P-256 public key
    // and the resulting server must be immediately usable for a full protocol round trip.
    OpaqueServer generated = OpaqueServer.generate(CONFIG);
    byte[] pk = generated.getServerPublicKey();

    // Compressed SEC1 P-256 point: 33 bytes, first byte 0x02 or 0x03.
    assertThat(pk).hasSize(33);
    assertThat(pk[0]).isIn((byte) 0x02, (byte) 0x03);

    OpaqueClient c = new OpaqueClient(CONFIG);
    ClientRegistrationState regState = c.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = c.finalizeRegistration(regState,
        generated.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER),
        null, null);

    ClientAuthState authState = c.generateKE1(PASSWORD_CORRECT);
    Object[] ke2Result = generated.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    KE2 ke2 = (KE2) ke2Result[1];
    ServerAuthState sas = (ServerAuthState) ke2Result[0];

    AuthResult result = c.generateKE3(authState, null, null, ke2);
    byte[] serverKey = generated.serverFinish(sas, result.ke3());
    assertThat(result.sessionKey()).isEqualTo(serverKey);
  }

  @Test
  void differentOprfSeedsCannotCrossAuthenticate() {
    // Two servers with identical long-term AKE keys but different OPRF seeds derive different
    // per-credential OPRF keys.  A user registered against server A cannot authenticate against
    // server B: the OPRF evaluation differs → different randomized_pwd → envelope auth_tag mismatch.
    //
    // A deterministic key pair is used so the only variable between the two servers is the seed.
    Object[] kp = com.codeheadsystems.opaque.internal.OpaqueCrypto.deriveAkeKeyPairFull(new byte[32]);
    java.math.BigInteger sharedSk = (java.math.BigInteger) kp[0];
    byte[] sharedPk = (byte[]) kp[1];
    byte[] rawSk = sharedSk.toByteArray();
    byte[] skFixed = new byte[32];
    if (rawSk.length > 32) {
      System.arraycopy(rawSk, rawSk.length - 32, skFixed, 0, 32);
    } else {
      System.arraycopy(rawSk, 0, skFixed, 32 - rawSk.length, rawSk.length);
    }

    byte[] seedA = com.codeheadsystems.opaque.internal.OpaqueCrypto.randomBytes(32);
    byte[] seedB = com.codeheadsystems.opaque.internal.OpaqueCrypto.randomBytes(32);
    OpaqueServer serverA = new OpaqueServer(skFixed, sharedPk, seedA, CONFIG);
    OpaqueServer serverB = new OpaqueServer(skFixed, sharedPk, seedB, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD_CORRECT);
    RegistrationRecord record = client.finalizeRegistration(regState,
        serverA.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER), null, null);

    assertThatThrownBy(() -> {
      ClientAuthState authState = client.generateKE1(PASSWORD_CORRECT);
      Object[] ke2Result = serverB.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
      client.generateKE3(authState, null, null, (KE2) ke2Result[1]);
    }).isInstanceOf(SecurityException.class)
      .hasMessageContaining("auth_tag mismatch");
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
}
