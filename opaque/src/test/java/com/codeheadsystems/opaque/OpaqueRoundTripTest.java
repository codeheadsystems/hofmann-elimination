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
}
