package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.model.OprfRequest;
import com.codeheadsystems.hofmann.model.OprfResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.opaque.Client;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.model.AuthResult;
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.CredentialResponse;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Dropwizard integration tests for {@link HofmannBundle}.
 * <p>
 * Starts a real embedded Jetty server using the test configuration (identity KSF,
 * ephemeral keys) and exercises the full OPAQUE registration + authentication flow
 * over HTTP.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class HofmannBundleIntegrationTest {

  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config.yml"));

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();
  private static final byte[] CREDENTIAL_ID = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  private Client opaqueClient;

  @BeforeEach
  void setUp() {
    // Context must match test-config.yml; identity KSF matches argon2MemoryKib: 0
    OpaqueConfig clientConfig = new OpaqueConfig(
        OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
        "hofmann-test".getBytes(StandardCharsets.UTF_8),
        new OpaqueConfig.IdentityKsf());
    opaqueClient = new Client(clientConfig);
  }

  // ── Health check ─────────────────────────────────────────────────────────

  @Test
  void healthCheckReportsHealthy() {
    Response response = APP.client()
        .target(String.format("http://localhost:%d/healthcheck", APP.getAdminPort()))
        .request()
        .get();

    assertThat(response.getStatus()).isEqualTo(200);
    String body = response.readEntity(String.class);
    // Dropwizard 5.x returns JSON: {"opaque-server":{"healthy":true,...}}
    assertThat(body).contains("opaque-server");
    assertThat(body).contains("\"healthy\":true");
  }

  // ── Registration ─────────────────────────────────────────────────────────

  @Test
  void registrationStartReturnsEvaluatedElement() {
    ClientRegistrationState state = opaqueClient.createRegistrationRequest(PASSWORD);

    RegistrationStartRequest req = new RegistrationStartRequest(
        B64.encodeToString(CREDENTIAL_ID),
        B64.encodeToString(state.request().blindedElement()));

    Response response = APP.client()
        .target(baseUrl() + "/opaque/registration/start")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(req));

    assertThat(response.getStatus()).isEqualTo(200);
    RegistrationStartResponse body = response.readEntity(RegistrationStartResponse.class);
    assertThat(body.evaluatedElementBase64()).isNotEmpty();
    assertThat(body.serverPublicKeyBase64()).isNotEmpty();
    // Compressed SEC1 point — first byte 0x02 or 0x03
    assertThat(B64D.decode(body.serverPublicKeyBase64())[0]).isIn((byte) 0x02, (byte) 0x03);
  }

  // ── Full registration + authentication round trip ─────────────────────────

  @Test
  void fullRegistrationThenAuthenticationSucceeds() {
    // ── Registration phase ────────────────────────────────────────────────
    ClientRegistrationState regState = opaqueClient.createRegistrationRequest(PASSWORD);

    RegistrationStartResponse startResp = APP.client()
        .target(baseUrl() + "/opaque/registration/start")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new RegistrationStartRequest(
            B64.encodeToString(CREDENTIAL_ID),
            B64.encodeToString(regState.request().blindedElement()))))
        .readEntity(RegistrationStartResponse.class);

    // Reconstruct RegistrationResponse for the client-side finalizeRegistration call
    RegistrationResponse registrationResponse = new RegistrationResponse(
        B64D.decode(startResp.evaluatedElementBase64()),
        B64D.decode(startResp.serverPublicKeyBase64()));

    RegistrationRecord record =
        opaqueClient.finalizeRegistration(regState, registrationResponse, null, null);

    // Send record to server
    Response finishResp = APP.client()
        .target(baseUrl() + "/opaque/registration/finish")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new RegistrationFinishRequest(
            B64.encodeToString(CREDENTIAL_ID),
            B64.encodeToString(record.clientPublicKey()),
            B64.encodeToString(record.maskingKey()),
            B64.encodeToString(record.envelope().envelopeNonce()),
            B64.encodeToString(record.envelope().authTag()))));

    assertThat(finishResp.getStatus()).isEqualTo(204);

    // ── Authentication phase ──────────────────────────────────────────────
    ClientAuthState authState = opaqueClient.generateKE1(PASSWORD);

    AuthStartResponse authStartResp = APP.client()
        .target(baseUrl() + "/opaque/auth/start")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new AuthStartRequest(
            B64.encodeToString(CREDENTIAL_ID),
            B64.encodeToString(authState.ke1().credentialRequest().blindedElement()),
            B64.encodeToString(authState.ke1().clientNonce()),
            B64.encodeToString(authState.ke1().clientAkePublicKey()))))
        .readEntity(AuthStartResponse.class);

    assertThat(authStartResp.sessionToken()).isNotEmpty();
    assertThat(authStartResp.serverMacBase64()).isNotEmpty();

    // Reconstruct KE2 for client-side generateKE3
    KE2 ke2 = new KE2(new CredentialResponse(
        B64D.decode(authStartResp.evaluatedElementBase64()),
        B64D.decode(authStartResp.maskingNonceBase64()),
        B64D.decode(authStartResp.maskedResponseBase64())),
        B64D.decode(authStartResp.serverNonceBase64()),
        B64D.decode(authStartResp.serverAkePublicKeyBase64()),
        B64D.decode(authStartResp.serverMacBase64()));

    AuthResult authResult = opaqueClient.generateKE3(authState, null, null, ke2);

    AuthFinishResponse authFinishResp = APP.client()
        .target(baseUrl() + "/opaque/auth/finish")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new AuthFinishRequest(
            authStartResp.sessionToken(),
            B64.encodeToString(authResult.ke3().clientMac()))))
        .readEntity(AuthFinishResponse.class);

    // Both sides derive the same session key
    assertThat(B64D.decode(authFinishResp.sessionKeyBase64()))
        .isEqualTo(authResult.sessionKey());
  }

  @Test
  void wrongPasswordReturns401() {
    // Register with correct password
    ClientRegistrationState regState = opaqueClient.createRegistrationRequest(PASSWORD);
    RegistrationStartResponse startResp = APP.client()
        .target(baseUrl() + "/opaque/registration/start")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new RegistrationStartRequest(
            B64.encodeToString("wrong-pwd-user@example.com".getBytes(StandardCharsets.UTF_8)),
            B64.encodeToString(regState.request().blindedElement()))))
        .readEntity(RegistrationStartResponse.class);

    RegistrationResponse registrationResponse =
        new RegistrationResponse(
            B64D.decode(startResp.evaluatedElementBase64()),
            B64D.decode(startResp.serverPublicKeyBase64()));
    RegistrationRecord record =
        opaqueClient.finalizeRegistration(regState, registrationResponse, null, null);

    byte[] wrongCredId = "wrong-pwd-user@example.com".getBytes(StandardCharsets.UTF_8);
    APP.client()
        .target(baseUrl() + "/opaque/registration/finish")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new RegistrationFinishRequest(
            B64.encodeToString(wrongCredId),
            B64.encodeToString(record.clientPublicKey()),
            B64.encodeToString(record.maskingKey()),
            B64.encodeToString(record.envelope().envelopeNonce()),
            B64.encodeToString(record.envelope().authTag()))));

    // Authenticate with wrong password — auth/start should succeed (fake or real KE2)
    // but generateKE3 on the client will throw SecurityException before even hitting auth/finish.
    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);
    ClientAuthState badAuthState = opaqueClient.generateKE1(wrongPassword);

    AuthStartResponse authStartResp = APP.client()
        .target(baseUrl() + "/opaque/auth/start")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new AuthStartRequest(
            B64.encodeToString(wrongCredId),
            B64.encodeToString(badAuthState.ke1().credentialRequest().blindedElement()),
            B64.encodeToString(badAuthState.ke1().clientNonce()),
            B64.encodeToString(badAuthState.ke1().clientAkePublicKey()))))
        .readEntity(AuthStartResponse.class);

    // Send a bogus KE3 (all-zeros client MAC) — server must reject with 401
    Response finishResp = APP.client()
        .target(baseUrl() + "/opaque/auth/finish")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new AuthFinishRequest(
            authStartResp.sessionToken(),
            B64.encodeToString(new byte[32]))));

    assertThat(finishResp.getStatus()).isEqualTo(401);
  }

  @Test
  void unknownSessionTokenReturns401() {
    Response response = APP.client()
        .target(baseUrl() + "/opaque/auth/finish")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(new AuthFinishRequest(
            "no-such-token",
            B64.encodeToString(new byte[32]))));

    assertThat(response.getStatus()).isEqualTo(401);
  }

  // ── OPRF ─────────────────────────────────────────────────────────────────

  @Test
  void oprfEvaluateReturnsValidResponse() {
    // Use the well-known P-256 generator point (compressed SEC1) as a stand-in for a
    // client-blinded point. In a real OPRF flow the client would blind its input with a
    // random scalar; here we use a hardcoded constant so the test needs no BouncyCastle types.
    String hexPoint = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    OprfRequest req = new OprfRequest(hexPoint, "test-request-id");

    Response response = APP.client()
        .target(baseUrl() + "/oprf")
        .request(MediaType.APPLICATION_JSON)
        .post(Entity.json(req));

    assertThat(response.getStatus()).isEqualTo(200);
    OprfResponse body = response.readEntity(OprfResponse.class);
    assertThat(body.hexCodedEcPoint()).isNotEmpty();
    assertThat(body.processIdentifier()).isEqualTo("test-processor");
    // Evaluated point must be a valid compressed SEC1 hex string (first byte 02 or 03)
    assertThat(body.hexCodedEcPoint()).matches("^(02|03)[0-9a-f]+$");
  }

  // ── Helper ───────────────────────────────────────────────────────────────

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }
}
