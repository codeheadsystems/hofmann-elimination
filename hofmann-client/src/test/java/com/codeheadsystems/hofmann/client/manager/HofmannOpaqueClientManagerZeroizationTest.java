package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationRequest;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Asserts that the manager actually <em>invokes</em> the state zeroization.
 *
 * <p>{@code ClientAuthState} and {@code ClientRegistrationState} have implemented
 * {@link AutoCloseable} for a long time, and a grep across every {@code src/main} tree found zero
 * {@code close()} calls and zero try-with-resources blocks on either. The mitigation existed and
 * never ran, which is worse than not having it — the docs claimed protection the code did not
 * provide. Unit tests on the records themselves could not catch that, because they construct the
 * state and close it by hand; the gap was in the caller.
 *
 * <p>So these tests reach into the manager's client cache and install a {@link Client} that
 * records every state it hands out, then assert that by the time the public method returns, every
 * one of them has been closed. Delete the try-with-resources in
 * {@link HofmannOpaqueClientManager} and these fail.
 *
 * <p>They also pin the other half of the contract: the caller's own password array is never
 * touched. That is what makes closing safe here at all — {@code authenticate()} passes the same
 * array on to {@code changePassword} when the server signals key rotation.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOpaqueClientManagerZeroizationTest {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueClientConfigResponse SERVER_CONFIG =
      new OpaqueClientConfigResponse("P256_SHA256", "opaque-zeroization-test", 0, 0, 0);
  private static final OpaqueConfig OPAQUE_CONFIG = new OpaqueConfig(
      OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
      "opaque-zeroization-test".getBytes(StandardCharsets.UTF_8),
      new OpaqueConfig.IdentityKsf(), new RandomProvider());

  @Mock private HofmannOpaqueAccessor accessor;
  private HofmannOpaqueClientManager manager;
  private RecordingClient recordingClient;

  /** A fresh array per test: these assert on its contents, so it must not be shared. */
  private byte[] password() {
    return "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
  }

  @BeforeEach
  void setUp() throws Exception {
    lenient().when(accessor.getOpaqueConfig(SERVER_ID)).thenReturn(SERVER_CONFIG);
    manager = new HofmannOpaqueClientManager(accessor, Collections.emptyMap(), true);
    recordingClient = new RecordingClient(OPAQUE_CONFIG);
    installClient(manager, SERVER_ID, recordingClient);
  }

  /**
   * Pre-populates the manager's lazily-built client cache so the manager uses a client we can
   * observe. The alternative — mocking construction — would replace the real cryptography, and
   * then the test would no longer be exercising the flow whose state lifetime is in question.
   */
  @SuppressWarnings("unchecked")
  private static void installClient(HofmannOpaqueClientManager manager,
                                    ServerIdentifier serverId, Client client) throws Exception {
    Field field = HofmannOpaqueClientManager.class.getDeclaredField("clientCache");
    field.setAccessible(true);
    ((Map<ServerIdentifier, Client>) field.get(manager)).put(serverId, client);
  }

  // ─── registration ───────────────────────────────────────────────────────────

  @Test
  void register_closesTheRegistrationState() {
    byte[] password = password();
    Server server = Server.generate(OPAQUE_CONFIG);
    when(accessor.registrationStart(eq(SERVER_ID), any(), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest req = inv.getArgument(1);
      return new RegistrationStartResponse(server.createRegistrationResponse(
          new RegistrationRequest(req.registrationRequest().blindedElement()), CREDENTIAL_ID));
    });

    manager.register(SERVER_ID, CREDENTIAL_ID, password);

    assertThat(recordingClient.registrationStates).hasSize(1);
    assertThat(recordingClient.registrationStates.get(0).password())
        .as("the state's copy of the password must be zeroed before register() returns")
        .containsOnly((byte) 0);
    assertThat(password)
        .as("the caller's array belongs to the caller")
        .isEqualTo(password());
  }

  /**
   * The failure path is the one that matters most in practice: a network error at step 1 is the
   * common case, and before the try-with-resources it left the password live on the heap for the
   * lifetime of the process.
   */
  @Test
  void register_closesTheRegistrationState_evenWhenTheServerCallFails() {
    byte[] password = password();
    when(accessor.registrationStart(eq(SERVER_ID), any(), any()))
        .thenThrow(new IllegalStateException("connection reset"));

    assertThatThrownBy(() -> manager.register(SERVER_ID, CREDENTIAL_ID, password))
        .isInstanceOf(IllegalStateException.class);

    assertThat(recordingClient.registrationStates).hasSize(1);
    assertThat(recordingClient.registrationStates.get(0).password()).containsOnly((byte) 0);
    assertThat(password).isEqualTo(password());
  }

  @Test
  void changePassword_closesTheRegistrationState() {
    byte[] newPassword = "a-brand-new-password".getBytes(StandardCharsets.UTF_8);
    Server server = Server.generate(OPAQUE_CONFIG);
    when(accessor.changePasswordStart(eq(SERVER_ID), any(), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest req = inv.getArgument(1);
      return new RegistrationStartResponse(server.createRegistrationResponse(
          new RegistrationRequest(req.registrationRequest().blindedElement()), CREDENTIAL_ID));
    });

    manager.changePassword(SERVER_ID, CREDENTIAL_ID, newPassword, "jwt");

    assertThat(recordingClient.registrationStates).hasSize(1);
    assertThat(recordingClient.registrationStates.get(0).password()).containsOnly((byte) 0);
  }

  // ─── authentication ─────────────────────────────────────────────────────────

  @Test
  void authenticate_closesTheAuthState() {
    byte[] password = password();
    RegistrationRecord record = registerDirectly(password);

    Server server = serverHolder[0];
    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);
      ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_ID, req.ke1(), null);
      when(accessor.authFinish(eq(SERVER_ID), any())).thenAnswer(finInv -> {
        com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest finReq = finInv.getArgument(1);
        byte[] sessionKey = server.serverFinish(ke2Result.serverAuthState(), finReq.ke3());
        return new AuthFinishResponse(B64.encodeToString(sessionKey), "test-jwt-token");
      });
      return new AuthStartResponse("session-token", ke2Result.ke2());
    });

    manager.authenticate(SERVER_ID, CREDENTIAL_ID, password);

    assertThat(recordingClient.authStates).hasSize(1);
    assertThat(recordingClient.authStates.get(0).password()).containsOnly((byte) 0);
    assertThat(password)
        .as("authenticate() may hand this same array to changePassword on key rotation")
        .isEqualTo(password());
  }

  /**
   * A wrong password throws out of {@code generateKE3}, which is the branch an online guessing
   * client drives repeatedly — so it is the branch most likely to accumulate residue.
   */
  @Test
  void authenticate_closesTheAuthState_whenTheServerMacFails() {
    RegistrationRecord record = registerDirectly(password());
    Server server = serverHolder[0];
    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);
      ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_ID, req.ke1(), null);
      return new AuthStartResponse("session-token", ke2Result.ke2());
    });

    assertThatThrownBy(() -> manager.authenticate(SERVER_ID, CREDENTIAL_ID, wrongPassword))
        .isInstanceOf(SecurityException.class);

    assertThat(recordingClient.authStates).hasSize(1);
    assertThat(recordingClient.authStates.get(0).password()).containsOnly((byte) 0);
    assertThat(wrongPassword).isEqualTo("wrong-password".getBytes(StandardCharsets.UTF_8));
  }

  /**
   * The key-rotation path re-enters registration with the caller's password <em>after</em> the
   * auth state is closed. If closing ever reverted to zeroing the caller's array, this would
   * silently re-register the account under an all-zero password — a far worse outcome than the
   * leak it was meant to fix, and one that would not throw. Hence a test for it specifically.
   */
  @Test
  void authenticate_withKeyRotation_reRegistersUnderTheOriginalPassword() {
    byte[] password = password();
    RegistrationRecord record = registerDirectly(password);
    Server server = serverHolder[0];

    when(accessor.authStart(eq(SERVER_ID), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.AuthStartRequest req = inv.getArgument(1);
      ServerKE2Result ke2Result = server.generateKE2(null, record, CREDENTIAL_ID, req.ke1(), null);
      when(accessor.authFinish(eq(SERVER_ID), any())).thenAnswer(finInv -> {
        com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest finReq = finInv.getArgument(1);
        byte[] sessionKey = server.serverFinish(ke2Result.serverAuthState(), finReq.ke3());
        return new AuthFinishResponse(B64.encodeToString(sessionKey), "jwt", true);
      });
      return new AuthStartResponse("session-token", ke2Result.ke2());
    });
    when(accessor.changePasswordStart(eq(SERVER_ID), any(), any())).thenAnswer(inv -> {
      com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest req = inv.getArgument(1);
      return new RegistrationStartResponse(server.createRegistrationResponse(
          new RegistrationRequest(req.registrationRequest().blindedElement()), CREDENTIAL_ID));
    });

    manager.authenticate(SERVER_ID, CREDENTIAL_ID, password);

    // The re-registration ran with the real password, not a zeroed buffer.
    assertThat(recordingClient.registrationPasswords).hasSize(1);
    assertThat(recordingClient.registrationPasswords.get(0)).isEqualTo(password());
    // And both states were closed.
    assertThat(recordingClient.authStates.get(0).password()).containsOnly((byte) 0);
    assertThat(recordingClient.registrationStates.get(0).password()).containsOnly((byte) 0);
  }

  // ─── helpers ────────────────────────────────────────────────────────────────

  private final Server[] serverHolder = new Server[1];

  /** Registers through the plain library client so the server has a record to authenticate. */
  private RegistrationRecord registerDirectly(byte[] password) {
    Server server = Server.generate(OPAQUE_CONFIG);
    serverHolder[0] = server;
    Client plain = new Client(OPAQUE_CONFIG);
    ClientRegistrationState state = plain.createRegistrationRequest(password);
    RegistrationResponse response = server.createRegistrationResponse(
        new RegistrationRequest(state.request().blindedElement()), CREDENTIAL_ID);
    return plain.finalizeRegistration(state, response, null, null);
  }

  /** Delegates to the real client and keeps every state it produced. */
  private static class RecordingClient extends Client {
    private final List<ClientRegistrationState> registrationStates = new ArrayList<>();
    private final List<ClientAuthState> authStates = new ArrayList<>();
    /** Copies of the password as it arrived, taken before the flow can touch anything. */
    private final List<byte[]> registrationPasswords = new ArrayList<>();

    RecordingClient(OpaqueConfig config) {
      super(config);
    }

    @Override
    public ClientRegistrationState createRegistrationRequest(byte[] password) {
      registrationPasswords.add(password.clone());
      ClientRegistrationState state = super.createRegistrationRequest(password);
      registrationStates.add(state);
      return state;
    }

    @Override
    public ClientAuthState generateKE1(byte[] password) {
      ClientAuthState state = super.generateKE1(password);
      authStates.add(state);
      return state;
    }
  }
}
