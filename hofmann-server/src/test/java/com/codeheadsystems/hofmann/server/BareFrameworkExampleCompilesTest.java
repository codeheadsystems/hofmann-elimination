package com.codeheadsystems.hofmann.server;

import static org.assertj.core.api.Assertions.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.manager.JwtManager;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * The bare-framework wiring in {@code docs/INTEGRATION.md} compiles and runs.
 *
 * <p>That document is the only instruction for integrators who use neither Dropwizard nor Spring
 * Boot, and its snippet had drifted into calling two things that do not exist: {@code
 * AkeKeyPair.privateKeyBytes()}, where the record exposes a {@code BigInteger privateKey()}, and
 * {@code OprfCipherSuite.P256_SHA256}, where the constant lives on {@code CurveHashSuite} and the
 * suite is built.
 *
 * <p>Being uncompilable is the mild half. The obvious repair for the first — {@code
 * privateKey().toByteArray()} — is silently wrong: {@code Server} decodes a fixed-width scalar in
 * the group's canonical encoding, big-endian on the NIST curves and little-endian on ristretto255,
 * and {@code toByteArray()} is neither fixed-width nor little-endian. It is right often enough on
 * P-256 to pass a smoke test.
 *
 * <p>Prose cannot be compiled, so this test is the mechanism: it performs the same calls in the
 * same order, and a signature change that invalidates the document fails here.
 */
class BareFrameworkExampleCompilesTest {

  private static byte[] hexToBytes(final String hex) {
    return HexFormat.of().parseHex(hex);
  }

  @Test
  void theDocumentedWiringCompilesAndProducesAServer() {
    // 1. Choose cipher suite and build config
    OpaqueConfig config = OpaqueConfig.withArgon2id(
        "my-app-v1".getBytes(UTF_8),   // context — must match every client
        65536, 3, 1                     // Argon2id memory KiB / iterations / parallelism
    );

    // 2. Derive the server key pair and OPRF seed from hex seeds
    byte[] serverKeySeed = hexToBytes("00".repeat(32));
    byte[] oprfSeed = hexToBytes("11".repeat(32));

    OpaqueCipherSuite suite = config.cipherSuite();
    OpaqueCipherSuite.AkeKeyPair kp = suite.deriveAkeKeyPair(serverKeySeed);

    byte[] privateKeyBytes = suite.oprfSuite().groupSpec().serializeScalar(kp.privateKey());

    Server server = new Server(privateKeyBytes, kp.publicKeyBytes(), oprfSeed, config);

    // 3. Build the standalone OPRF supplier (supports hot key rotation)
    BigInteger masterKey = new BigInteger(1, hexToBytes("22".repeat(32)));
    Supplier<ServerProcessorDetail> oprfSupplier =
        () -> new ServerProcessorDetail(masterKey, "key-v1");

    // 4. Provide persistent credential and session stores
    CredentialStore credentialStore = new InMemoryCredentialStore();
    SessionStore sessionStore = new InMemorySessionStore();

    // 5. Build the JWT manager (supports key rotation via Supplier<JwtKeyDetail>)
    byte[] jwtSecret = hexToBytes("33".repeat(32));
    JwtManager jwt = new JwtManager(jwtSecret, "my-app", 3600L, sessionStore);

    // 6. Build the framework-agnostic protocol manager
    HofmannOpaqueServerManager manager =
        new HofmannOpaqueServerManager(server, credentialStore, jwt);

    // 7. Optionally build the standalone OPRF manager
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256)
        .build();
    OprfServerManager oprfManager = new OprfServerManager(oprfSuite, oprfSupplier);

    assertThat(manager).isNotNull();
    assertThat(oprfManager).isNotNull();
  }

  /**
   * The scalar encoding is the part a reader is most likely to "fix" wrongly, so pin the
   * difference rather than only the correct call.
   */
  @Test
  void serializeScalarIsFixedWidthAndToByteArrayIsNot() {
    OpaqueCipherSuite suite = OpaqueConfig
        .withArgon2id("ctx".getBytes(UTF_8), 65536, 3, 1)
        .cipherSuite();

    // A private key small enough that BigInteger drops the leading zero bytes.
    OpaqueCipherSuite.AkeKeyPair kp = suite.deriveAkeKeyPair(new byte[32]);
    BigInteger sk = BigInteger.ONE;

    byte[] canonical = suite.oprfSuite().groupSpec().serializeScalar(sk);
    byte[] naive = sk.toByteArray();

    assertThat(canonical)
        .as("serializeScalar pads to the group's scalar width, which is what Server decodes")
        .hasSize(suite.oprfSuite().groupSpec().scalarSize());
    assertThat(naive)
        .as("toByteArray is minimal-width, so it is not interchangeable")
        .hasSize(1);
    assertThat(kp.publicKeyBytes()).isNotEmpty();
  }
}
