package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.OpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link OpaqueManager}.
 * <p>
 * Uses the real opaque {@link com.codeheadsystems.opaque.Client} with a P-256 / identity-KSF
 * test config so that all cryptographic operations execute correctly, while the
 * {@link OpaqueAccessor} HTTP layer is mocked out.
 */
@ExtendWith(MockitoExtension.class)
class OpaqueManagerTest {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  @Mock private OpaqueAccessor accessor;

  private OpaqueManager manager;

  // A real opaque Client is used via OpaqueManager so we can exercise the full crypto path.
  // We use the identity KSF and a fixed context so the test is deterministic (no Argon2 cost).
  private static final OpaqueClientConfig CONFIG = OpaqueClientConfig.forTesting("opaque-manager-test");

  @BeforeEach
  void setUp() {
    manager = new OpaqueManager(CONFIG, accessor);
  }

  @Test
  void register_callsAllThreeEndpoints() {
    // The registration start response must carry valid base64 that the real Client can process.
    // We run a real server-side registration here by embedding the opaque Server in the test.
    com.codeheadsystems.opaque.Server server =
        com.codeheadsystems.opaque.Server.generate(CONFIG.opaqueConfig());

    // Simulate server's registration start response
    com.codeheadsystems.opaque.model.RegistrationRequest regReq =
        new com.codeheadsystems.opaque.model.RegistrationRequest(new byte[33]); // placeholder

    // Do the full registration via manager by having the accessor mock return real server outputs
    com.codeheadsystems.opaque.Client realClient = new com.codeheadsystems.opaque.Client(CONFIG.opaqueConfig());
    com.codeheadsystems.opaque.model.ClientRegistrationState regState =
        realClient.createRegistrationRequest(PASSWORD);

    com.codeheadsystems.opaque.model.RegistrationResponse regResp =
        server.createRegistrationResponse(
            new com.codeheadsystems.opaque.model.RegistrationRequest(
                regState.request().blindedElement()),
            CREDENTIAL_ID);

    RegistrationStartResponse startResponse = new RegistrationStartResponse(
        B64.encodeToString(regResp.evaluatedElement()),
        B64.encodeToString(regResp.serverPublicKey()));

    when(accessor.registrationStart(eq(SERVER_ID), any())).thenReturn(startResponse);

    manager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    verify(accessor).registrationStart(eq(SERVER_ID), any());
    verify(accessor).registrationFinish(eq(SERVER_ID), any());
  }

  @Test
  void authenticate_successfulHandshake_returnsSessionKey() {
    com.codeheadsystems.opaque.Server server =
        com.codeheadsystems.opaque.Server.generate(CONFIG.opaqueConfig());

    // First do a real registration so the server has the record
    com.codeheadsystems.opaque.Client realClient = new com.codeheadsystems.opaque.Client(CONFIG.opaqueConfig());
    com.codeheadsystems.opaque.model.ClientRegistrationState regState =
        realClient.createRegistrationRequest(PASSWORD);
    com.codeheadsystems.opaque.model.RegistrationResponse regResp =
        server.createRegistrationResponse(
            new com.codeheadsystems.opaque.model.RegistrationRequest(
                regState.request().blindedElement()),
            CREDENTIAL_ID);
    com.codeheadsystems.opaque.model.RegistrationRecord record =
        realClient.finalizeRegistration(regState, regResp, null, null);

    // Now set up auth: have accessor return a real KE2 from the server
    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);
      byte[] blindedElement = Base64.getDecoder().decode(req.blindedElementBase64());
      byte[] clientNonce = Base64.getDecoder().decode(req.clientNonceBase64());
      byte[] clientAkePk = Base64.getDecoder().decode(req.clientAkePublicKeyBase64());

      com.codeheadsystems.opaque.model.KE1 ke1 = new com.codeheadsystems.opaque.model.KE1(
          new com.codeheadsystems.opaque.model.CredentialRequest(blindedElement),
          clientNonce, clientAkePk);

      com.codeheadsystems.opaque.model.ServerKE2Result ke2Result =
          server.generateKE2(null, record, CREDENTIAL_ID, ke1, null);

      // Stash server auth state so we can use it in authFinish
      com.codeheadsystems.opaque.model.KE2 ke2 = ke2Result.ke2();
      when(accessor.authFinish(eq(SERVER_ID), any())).thenAnswer(finInv -> {
        com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest finReq = finInv.getArgument(1);
        byte[] clientMac = Base64.getDecoder().decode(finReq.clientMacBase64());
        byte[] sessionKey = server.serverFinish(ke2Result.serverAuthState(),
            new com.codeheadsystems.opaque.model.KE3(clientMac));
        return new AuthFinishResponse(B64.encodeToString(sessionKey), "test-jwt-token");
      });

      return new AuthStartResponse(
          "session-token",
          B64.encodeToString(ke2.credentialResponse().evaluatedElement()),
          B64.encodeToString(ke2.credentialResponse().maskingNonce()),
          B64.encodeToString(ke2.credentialResponse().maskedResponse()),
          B64.encodeToString(ke2.serverNonce()),
          B64.encodeToString(ke2.serverAkePublicKey()),
          B64.encodeToString(ke2.serverMac()));
    });

    AuthFinishResponse response = manager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    assertThat(response.sessionKeyBase64()).isNotEmpty();
    assertThat(response.token()).isEqualTo("test-jwt-token");
    verify(accessor).authStart(eq(SERVER_ID), any());
    verify(accessor).authFinish(eq(SERVER_ID), any());
  }

  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    com.codeheadsystems.opaque.Server server =
        com.codeheadsystems.opaque.Server.generate(CONFIG.opaqueConfig());

    // Register with the correct password
    com.codeheadsystems.opaque.Client realClient = new com.codeheadsystems.opaque.Client(CONFIG.opaqueConfig());
    com.codeheadsystems.opaque.model.ClientRegistrationState regState =
        realClient.createRegistrationRequest(PASSWORD);
    com.codeheadsystems.opaque.model.RegistrationResponse regResp =
        server.createRegistrationResponse(
            new com.codeheadsystems.opaque.model.RegistrationRequest(
                regState.request().blindedElement()),
            CREDENTIAL_ID);
    com.codeheadsystems.opaque.model.RegistrationRecord record =
        realClient.finalizeRegistration(regState, regResp, null, null);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    // Auth start: server generates KE2 with the real record
    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);
      byte[] blindedElement = Base64.getDecoder().decode(req.blindedElementBase64());
      byte[] clientNonce = Base64.getDecoder().decode(req.clientNonceBase64());
      byte[] clientAkePk = Base64.getDecoder().decode(req.clientAkePublicKeyBase64());

      com.codeheadsystems.opaque.model.KE1 ke1 = new com.codeheadsystems.opaque.model.KE1(
          new com.codeheadsystems.opaque.model.CredentialRequest(blindedElement),
          clientNonce, clientAkePk);

      com.codeheadsystems.opaque.model.ServerKE2Result ke2Result =
          server.generateKE2(null, record, CREDENTIAL_ID, ke1, null);
      com.codeheadsystems.opaque.model.KE2 ke2 = ke2Result.ke2();

      return new AuthStartResponse(
          "session-token",
          B64.encodeToString(ke2.credentialResponse().evaluatedElement()),
          B64.encodeToString(ke2.credentialResponse().maskingNonce()),
          B64.encodeToString(ke2.credentialResponse().maskedResponse()),
          B64.encodeToString(ke2.serverNonce()),
          B64.encodeToString(ke2.serverAkePublicKey()),
          B64.encodeToString(ke2.serverMac()));
    });

    // The client will fail to verify the server MAC when using the wrong password,
    // so generateKE3 throws SecurityException before authFinish is even called.
    assertThatThrownBy(() -> manager.authenticate(SERVER_ID, CREDENTIAL_ID, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void deleteRegistration_callsAccessor() {
    manager.deleteRegistration(SERVER_ID, CREDENTIAL_ID);
    verify(accessor).registrationDelete(eq(SERVER_ID), any());
  }
}
