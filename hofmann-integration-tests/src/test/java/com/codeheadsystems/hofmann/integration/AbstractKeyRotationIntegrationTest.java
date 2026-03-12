package com.codeheadsystems.hofmann.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.config.OpaqueClientConfig;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * Base test class for OPAQUE key rotation integration tests.
 * <p>
 * Registers a credential under the initial server keys, then rotates to new keys
 * and verifies that authentication triggers automatic client-side re-registration
 * (migration) via the {@code keyRotationRequired} flag.
 */
abstract class AbstractKeyRotationIntegrationTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] PASSWORD = "rotation-test-password".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  @Autowired
  private MutableKeyDetailSupplier keyDetailSupplier;

  @Autowired
  private OpaqueConfig opaqueConfig;

  private HofmannOpaqueClientManager manager;

  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() {
    OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
        cipherSuiteName(), "integration-test", 1024, 1, 1);
    Map<ServerIdentifier, ServerConnectionInfo> connections = Map.of(
        SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl())));
    HofmannOpaqueAccessor accessor = new HofmannOpaqueAccessor(
        HttpClient.newHttpClient(), new ObjectMapper(), connections);
    manager = new HofmannOpaqueClientManager(accessor, Map.of(SERVER_ID, config));
  }

  @AfterEach
  void tearDown() {
    // Reset to initial single-key state to avoid contaminating other tests
    keyDetailSupplier.reset();
  }

  @Test
  void registerUnderOldKeys_rotateKeys_authenticateAutoMigrates() {
    byte[] credId = uniqueCredId("rotation-migrate");

    // Register under version 0
    manager.register(SERVER_ID, credId, PASSWORD);

    // Rotate to version 1
    Server newServer = Server.generate(opaqueConfig);
    keyDetailSupplier.rotateKeys(newServer);

    // First authenticate — should succeed using old keys (version 0)
    // and auto-migrate via changePassword (keyRotationRequired=true)
    AuthFinishResponse resp1 = manager.authenticate(SERVER_ID, credId, PASSWORD);
    assertThat(resp1.token()).isNotEmpty();
    assertThat(resp1.keyRotationRequired()).isTrue();

    // Second authenticate — should succeed using new keys (version 1)
    // with no rotation flag
    AuthFinishResponse resp2 = manager.authenticate(SERVER_ID, credId, PASSWORD);
    assertThat(resp2.token()).isNotEmpty();
    assertThat(resp2.keyRotationRequired()).isNull();
  }

  @Test
  void registerUnderOldKeys_rotateKeys_wrongPasswordStillFails() {
    byte[] credId = uniqueCredId("rotation-wrong-pwd");
    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

    manager.register(SERVER_ID, credId, PASSWORD);

    // Rotate keys
    keyDetailSupplier.rotateKeys(Server.generate(opaqueConfig));

    // Wrong password should still fail even with rotation active
    assertThatThrownBy(() -> manager.authenticate(SERVER_ID, credId, wrongPassword))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void registerAfterRotation_authenticatesNormally() {
    byte[] credId = uniqueCredId("rotation-new-reg");

    // Rotate first
    keyDetailSupplier.rotateKeys(Server.generate(opaqueConfig));

    // Register new credential under version 1
    manager.register(SERVER_ID, credId, PASSWORD);

    // Authenticate — should succeed at current version, no rotation flag
    AuthFinishResponse resp = manager.authenticate(SERVER_ID, credId, PASSWORD);
    assertThat(resp.token()).isNotEmpty();
    assertThat(resp.keyRotationRequired()).isNull();
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", port);
  }

  private byte[] uniqueCredId(String suffix) {
    return (cipherSuiteName() + "-" + suffix + "@rotation.test").getBytes(StandardCharsets.UTF_8);
  }
}
