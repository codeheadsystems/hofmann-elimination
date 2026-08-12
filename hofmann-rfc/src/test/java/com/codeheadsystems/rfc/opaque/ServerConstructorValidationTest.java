package com.codeheadsystems.rfc.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.testfixtures.OpaqueTestConfigs;
import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Validation performed by the {@link Server} constructor.
 *
 * <p>None of it had a test. The constructor's own javadoc says it "previously validated nothing at
 * all, so a misconfigured deployment started cleanly and failed later as an authentication error
 * with no indication of the cause" — the checks were added in response to that, and then left
 * unpinned. {@code OpaqueRoundTripTest} narrates the public-key mismatch case in a comment and
 * then avoids exercising it.
 *
 * <p>Run against every suite, because two of the four checks route through per-suite scalar
 * encoding: ristretto255 serializes scalars little-endian while the NIST suites are big-endian,
 * so a check that holds on one encoding is not evidence about the other.
 */
class ServerConstructorValidationTest {

  static Stream<OpaqueCipherSuite> allSuites() {
    return Stream.of(
        OpaqueCipherSuite.P256_SHA256,
        OpaqueCipherSuite.P384_SHA384,
        OpaqueCipherSuite.P521_SHA512,
        OpaqueCipherSuite.RISTRETTO255_SHA512);
  }

  private static OpaqueConfig configFor(OpaqueCipherSuite suite) {
    return OpaqueTestConfigs.forTesting(suite);
  }

  /** A valid (private, public) pair plus a correctly sized OPRF seed for the suite. */
  private record KeyMaterial(byte[] privateKey, byte[] publicKey, byte[] oprfSeed) {
  }

  private static KeyMaterial validKeyMaterial(OpaqueConfig config) {
    BigInteger sk = config.cipherSuite().oprfSuite().randomScalar();
    return new KeyMaterial(
        config.cipherSuite().oprfSuite().groupSpec().serializeScalar(sk),
        config.cipherSuite().oprfSuite().groupSpec().scalarMultiplyGenerator(sk),
        config.randomProvider().randomBytes(config.Nh()));
  }

  /**
   * The positive control. Without it, every rejection below would pass against a constructor that
   * refused all input.
   */
  @ParameterizedTest
  @MethodSource("allSuites")
  void validKeyMaterialIsAccepted(OpaqueCipherSuite suite) {
    OpaqueConfig config = configFor(suite);
    KeyMaterial km = validKeyMaterial(config);

    assertThatCode(() -> new Server(km.privateKey(), km.publicKey(), km.oprfSeed(), config))
        .doesNotThrowAnyException();
  }

  @ParameterizedTest
  @MethodSource("allSuites")
  void nullConfigIsRejected(OpaqueCipherSuite suite) {
    KeyMaterial km = validKeyMaterial(configFor(suite));

    assertThatThrownBy(() -> new Server(km.privateKey(), km.publicKey(), km.oprfSeed(), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("config is required");
  }

  @ParameterizedTest
  @MethodSource("allSuites")
  void nullKeyMaterialIsRejected(OpaqueCipherSuite suite) {
    OpaqueConfig config = configFor(suite);
    KeyMaterial km = validKeyMaterial(config);

    assertThatThrownBy(() -> new Server(null, km.publicKey(), km.oprfSeed(), config))
        .as("null private key")
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("key material is required");
    assertThatThrownBy(() -> new Server(km.privateKey(), null, km.oprfSeed(), config))
        .as("null public key")
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("key material is required");
    assertThatThrownBy(() -> new Server(km.privateKey(), km.publicKey(), null, config))
        .as("null OPRF seed")
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("key material is required");
  }

  /**
   * The one that is actively unsafe rather than merely wrong. A private key congruent to zero mod
   * the group order makes dh2 yield the identity for every client, so the long-term server key
   * stops contributing to the AKE at all — and because the failure is silent, the deployment looks
   * healthy.
   */
  @ParameterizedTest
  @MethodSource("allSuites")
  void privateKeyCongruentToZeroIsRejected(OpaqueCipherSuite suite) {
    OpaqueConfig config = configFor(suite);
    KeyMaterial km = validKeyMaterial(config);
    byte[] zeroScalar =
        config.cipherSuite().oprfSuite().groupSpec().serializeScalar(BigInteger.ZERO);

    assertThatThrownBy(() -> new Server(zeroScalar, km.publicKey(), km.oprfSeed(), config))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("congruent to zero");
  }

  /**
   * A well-formed public key that is not the one the private key derives. This authenticates
   * nothing: the client verifies the envelope against the public key it recovered, then runs dh2
   * against a private key that does not correspond to it, so every login fails <em>after</em> the
   * password has already been proven correct.
   */
  @ParameterizedTest
  @MethodSource("allSuites")
  void publicKeyNotMatchingThePrivateKeyIsRejected(OpaqueCipherSuite suite) {
    OpaqueConfig config = configFor(suite);
    KeyMaterial mine = validKeyMaterial(config);
    KeyMaterial other = validKeyMaterial(config);

    assertThatThrownBy(() ->
        new Server(mine.privateKey(), other.publicKey(), mine.oprfSeed(), config))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("does not match");
  }

  /**
   * The constructor copies the seed and the public key rather than aliasing them. Mutating the
   * caller's array afterwards would otherwise change the OPRF key for every credential, or place
   * a public key the private key does not correspond to into CleartextCredentials — past the
   * match check above, which is the only thing that would have caught it.
   *
   * <p>The seed half is asserted behaviourally rather than through an accessor, because there is
   * no getter for it: the same registration request, evaluated by the same server before and
   * after the caller's seed array is overwritten, must produce the same response. That response
   * is an OPRF evaluation under a key derived from the seed, so an aliased seed changes it.
   */
  @ParameterizedTest
  @MethodSource("allSuites")
  void keyMaterialIsCopiedRatherThanAliased(OpaqueCipherSuite suite) {
    OpaqueConfig config = configFor(suite);
    KeyMaterial km = validKeyMaterial(config);
    byte[] seed = km.oprfSeed().clone();
    byte[] publicKey = km.publicKey().clone();

    Server server = new Server(km.privateKey(), publicKey, seed, config);
    byte[] publicKeyBefore = server.getServerPublicKey().clone();

    // A fixed request, so the only thing that can change the response is the server's own state.
    byte[] credentialIdentifier = "alias-check".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    ClientRegistrationState regState =
        new Client(config).createRegistrationRequest("pw".getBytes(
            java.nio.charset.StandardCharsets.UTF_8));
    byte[] evaluatedBefore = server
        .createRegistrationResponse(regState.request(), credentialIdentifier).evaluatedElement();

    java.util.Arrays.fill(seed, (byte) 0xAA);
    java.util.Arrays.fill(publicKey, (byte) 0xBB);

    assertThat(server.getServerPublicKey())
        .as("the server's public key must not follow the caller's array")
        .isEqualTo(publicKeyBefore);
    assertThat(server.createRegistrationResponse(regState.request(), credentialIdentifier)
        .evaluatedElement())
        .as("the OPRF key must not follow the caller's seed array")
        .isEqualTo(evaluatedBefore);
  }
}
