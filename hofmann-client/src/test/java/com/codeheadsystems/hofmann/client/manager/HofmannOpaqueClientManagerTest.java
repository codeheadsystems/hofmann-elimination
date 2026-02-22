package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationRequest;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link HofmannOpaqueClientManager}.
 * <p>
 * Uses the real opaque {@link Client} with a P-256 / identity-KSF
 * test config so that all cryptographic operations execute correctly, while the
 * {@link HofmannOpaqueAccessor} HTTP layer is mocked out.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOpaqueClientManagerTest {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
  // A real opaque Client is used via OpaqueManager so we can exercise the full crypto path.
  // We use the identity KSF and a fixed context so the test is deterministic (no Argon2 cost).
  private static final OpaqueClientConfig CONFIG = OpaqueClientConfig.forTesting("opaque-manager-test");
  @Mock private HofmannOpaqueAccessor accessor;
  private HofmannOpaqueClientManager manager;

  @BeforeEach
  void setUp() {
    manager = new HofmannOpaqueClientManager(CONFIG, accessor);
  }

  @Test
  void register_callsAllThreeEndpoints() {
    Server server =
        Server.generate(CONFIG.opaqueConfig());

    // Do the full registration via manager by having the accessor mock return real server outputs
    Client realClient = new Client(CONFIG.opaqueConfig());
    ClientRegistrationState regState =
        realClient.createRegistrationRequest(PASSWORD);

    RegistrationResponse regResp =
        server.createRegistrationResponse(
            new RegistrationRequest(
                regState.request().blindedElement()),
            CREDENTIAL_ID);

    when(accessor.registrationStart(eq(SERVER_ID), any()))
        .thenReturn(new RegistrationStartResponse(regResp));

    manager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    verify(accessor).registrationStart(eq(SERVER_ID), any());
    verify(accessor).registrationFinish(eq(SERVER_ID), any());
  }

  @Test
  void authenticate_successfulHandshake_returnsSessionKey() {
    Server server =
        Server.generate(CONFIG.opaqueConfig());

    // First do a real registration so the server has the record
    Client realClient = new Client(CONFIG.opaqueConfig());
    ClientRegistrationState regState =
        realClient.createRegistrationRequest(PASSWORD);
    RegistrationResponse regResp =
        server.createRegistrationResponse(
            new RegistrationRequest(
                regState.request().blindedElement()),
            CREDENTIAL_ID);
    RegistrationRecord record =
        realClient.finalizeRegistration(regState, regResp, null, null);

    // Now set up auth: have accessor return a real KE2 from the server
    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);

      ServerKE2Result ke2Result =
          server.generateKE2(null, record, CREDENTIAL_ID, req.ke1(), null);

      // Stash server auth state so we can use it in authFinish
      when(accessor.authFinish(eq(SERVER_ID), any())).thenAnswer(finInv -> {
        com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest finReq = finInv.getArgument(1);
        byte[] sessionKey = server.serverFinish(ke2Result.serverAuthState(), finReq.ke3());
        return new AuthFinishResponse(B64.encodeToString(sessionKey), "test-jwt-token");
      });

      return new AuthStartResponse("session-token", ke2Result.ke2());
    });

    AuthFinishResponse response = manager.authenticate(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    assertThat(response.sessionKeyBase64()).isNotEmpty();
    assertThat(response.token()).isEqualTo("test-jwt-token");
    verify(accessor).authStart(eq(SERVER_ID), any());
    verify(accessor).authFinish(eq(SERVER_ID), any());
  }

  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    Server server =
        Server.generate(CONFIG.opaqueConfig());

    // Register with the correct password
    Client realClient = new Client(CONFIG.opaqueConfig());
    ClientRegistrationState regState =
        realClient.createRegistrationRequest(PASSWORD);
    RegistrationResponse regResp =
        server.createRegistrationResponse(
            new RegistrationRequest(
                regState.request().blindedElement()),
            CREDENTIAL_ID);
    RegistrationRecord record =
        realClient.finalizeRegistration(regState, regResp, null, null);

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    // Auth start: server generates KE2 with the real record
    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);
      ServerKE2Result ke2Result =
          server.generateKE2(null, record, CREDENTIAL_ID, req.ke1(), null);
      return new AuthStartResponse("session-token", ke2Result.ke2());
    });

    // The client will fail to verify the server MAC when using the wrong password,
    // so generateKE3 throws SecurityException before authFinish is even called.
    assertThatThrownBy(() -> manager.authenticate(SERVER_ID, CREDENTIAL_ID, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void deleteRegistration_callsAccessorWithToken() {
    manager.deleteRegistration(SERVER_ID, CREDENTIAL_ID, "test-jwt-token");
    verify(accessor).registrationDelete(eq(SERVER_ID), any(), eq("test-jwt-token"));
  }
}
