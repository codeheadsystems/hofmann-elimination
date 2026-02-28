package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.common.RandomProvider;
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
 * Config is fetched lazily via the mocked accessor's {@code getOpaqueConfig} method.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOpaqueClientManagerTest {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
  // OpaqueClientConfigResponse with argon2MemoryKib=0 triggers forTesting("opaque-manager-test")
  // which is identical to the old CONFIG used in earlier tests.
  private static final OpaqueClientConfigResponse SERVER_CONFIG =
      new OpaqueClientConfigResponse("P256_SHA256", "opaque-manager-test", 0, 0, 0);

  // Resolved config used for direct Server/Client construction in tests
  private static final OpaqueConfig OPAQUE_CONFIG = new OpaqueConfig(
      OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
      "opaque-manager-test".getBytes(StandardCharsets.UTF_8),
      new OpaqueConfig.IdentityKsf(), new RandomProvider());

  @Mock private HofmannOpaqueAccessor accessor;
  private HofmannOpaqueClientManager manager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    lenient().when(accessor.getOpaqueConfig(SERVER_ID)).thenReturn(SERVER_CONFIG);
    manager = new HofmannOpaqueClientManager(accessor);
  }

  /**
   * Register calls all three endpoints.
   */
  @Test
  void register_callsAllThreeEndpoints() {
    Server server = Server.generate(OPAQUE_CONFIG);

    // Do the full registration via manager by having the accessor mock return real server outputs
    Client realClient = new Client(OPAQUE_CONFIG);
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

  /**
   * Config is fetched exactly once and cached across multiple calls to the same server.
   */
  @Test
  void register_configFetchedOnce_whenCalledTwice() {
    Server server = Server.generate(OPAQUE_CONFIG);

    Client realClient = new Client(OPAQUE_CONFIG);

    // First call
    ClientRegistrationState regState1 = realClient.createRegistrationRequest(PASSWORD);
    RegistrationResponse regResp1 = server.createRegistrationResponse(
        new RegistrationRequest(regState1.request().blindedElement()), CREDENTIAL_ID);
    when(accessor.registrationStart(eq(SERVER_ID), any()))
        .thenReturn(new RegistrationStartResponse(regResp1));

    manager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    // Second call — reset the start stub
    ClientRegistrationState regState2 = realClient.createRegistrationRequest(PASSWORD);
    RegistrationResponse regResp2 = server.createRegistrationResponse(
        new RegistrationRequest(regState2.request().blindedElement()), CREDENTIAL_ID);
    when(accessor.registrationStart(eq(SERVER_ID), any()))
        .thenReturn(new RegistrationStartResponse(regResp2));

    manager.register(SERVER_ID, CREDENTIAL_ID, PASSWORD);

    // Config should have been fetched exactly once
    verify(accessor, times(1)).getOpaqueConfig(SERVER_ID);
  }

  /**
   * Authenticate successful handshake returns session key.
   */
  @Test
  void authenticate_successfulHandshake_returnsSessionKey() {
    Server server = Server.generate(OPAQUE_CONFIG);

    // First do a real registration so the server has the record
    Client realClient = new Client(OPAQUE_CONFIG);
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

  /**
   * Authenticate wrong password throws security exception.
   */
  @Test
  void authenticate_wrongPassword_throwsSecurityException() {
    Server server = Server.generate(OPAQUE_CONFIG);

    // Register with the correct password
    Client realClient = new Client(OPAQUE_CONFIG);
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

  /**
   * Delete registration calls accessor with token.
   */
  @Test
  void deleteRegistration_callsAccessorWithToken() {
    manager.deleteRegistration(SERVER_ID, CREDENTIAL_ID, "test-jwt-token");
    verify(accessor).registrationDelete(eq(SERVER_ID), any(), eq("test-jwt-token"));
  }
}
