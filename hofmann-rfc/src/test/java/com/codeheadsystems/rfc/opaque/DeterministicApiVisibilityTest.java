package com.codeheadsystems.rfc.opaque;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The deterministic test-vector entry points stay off the public API.
 *
 * <p>They were public with nothing but a {@code (for testing)} javadoc between them and a
 * production caller, and every way of misusing them is silent — the protocol keeps working and
 * produces plausible output. In severity order, <strong>corrected after review</strong>:
 *
 * <ul>
 *   <li>A client using a <em>published</em> blind — which is what pasting a constant out of the
 *       RFC's test vectors gives you — leaks the password outright.
 *       {@code blindedElement = blind · H(password)}, so an attacker who knows the blind computes
 *       {@code blind · H(guess)} and compares, recovering the password offline from
 *       <strong>one passively observed KE1</strong>. No server interaction, no compromise, no
 *       second account. A reviewer demonstrated this against this code.
 *   <li>A server reusing {@code (maskingNonce, serverAkeKeySeed, serverNonce)} makes the whole
 *       KE2 a function of the client's KE1, so a recorded exchange replays: an attacker who saw
 *       one successful authentication can authenticate again <strong>without the password</strong>.
 *       Demonstrated as well — every KE2 field byte-identical, {@code serverFinish} returning the
 *       honest session key.
 *   <li>Reusing {@code serverAkeKeySeed} alone destroys <em>forward secrecy</em>: a later server
 *       compromise yields the long-term key and the fixed ephemeral together and retroactively
 *       opens every recorded session, where it would normally yield only {@code dh2}. An earlier
 *       version of this list said "one compromised ephemeral key opens every past and future
 *       session", which is false — {@code dh2 = serverStaticSk · clientAkePk} does not involve
 *       the ephemeral at all, and the long-term key is required too.
 *   <li>Reusing the client AKE seed makes a user's sessions linkable across logins, since
 *       {@code clientAkePublicKey} is wire-visible and stable while everything else varies.
 * </ul>
 *
 * <p>A javadoc line is not a control. This asserts the visibility so that widening one back is a
 * deliberate act with a failing test attached, rather than something that happens because an IDE
 * offered to make a method public to satisfy a caller in another package.
 *
 * <p><strong>On its own this asserts a habit, not a boundary</strong> — it did overclaim one once,
 * while the same five capabilities were public in {@code ...opaque.internal}. The boundary is
 * {@link PackageBoundaryTest}, which pins the whole public surface of this package by signature,
 * plus the jar sealing checked by {@code :hofmann-rfc:verifyOpaquePackageSealed}. This test is
 * kept alongside it because it is the one that says <em>why</em> each of these five parameters
 * matters, and that reasoning is what someone about to widen one needs to read.
 */
class DeterministicApiVisibilityTest {

  private static List<Method> deterministicMethods() {
    return java.util.stream.Stream.of(Client.class.getDeclaredMethods(),
            Server.class.getDeclaredMethods())
        .flatMap(java.util.Arrays::stream)
        .filter(m -> m.getName().endsWith("Deterministic"))
        .toList();
  }

  /**
   * Excludes {@code protected} as well as {@code public}.
   *
   * <p>{@link Modifier#isPublic} alone was too loose: {@code Client} and {@code Server} are both
   * public and non-final, so a {@code protected} method passes that check and is still reachable
   * by a consumer subclass in any package. A reviewer confirmed the looser assertion passed on a
   * protected stand-in.
   */
  @ParameterizedTest
  @MethodSource("deterministicMethods")
  void isNotReachableFromOutsideThePackage(Method method) {
    assertThat(method.getModifiers() & (Modifier.PUBLIC | Modifier.PROTECTED))
        .as("%s.%s must be neither public nor protected — these classes are subclassable",
            method.getDeclaringClass().getSimpleName(), method.getName())
        .isZero();
  }

  /**
   * Pins the count, so a rename cannot quietly shrink what the test above covers.
   *
   * <p>Not, as this originally claimed, because an empty argument list would pass vacuously — on
   * JUnit 6 that is a hard error ({@code You must configure at least one set of arguments}) unless
   * {@code allowZeroInvocations} is set. The real hazard is subtler and this does address it: a
   * rename that drops one method from the filter leaves the parameterised test green on four.
   *
   * <p>Note the filter is name-based, so it sees only methods called {@code *Deterministic}.
   * {@code OpaqueAke.generateKE2} takes {@code maskingNonce} and {@code serverAkeKeySeed} as
   * parameters and is invisible to it by construction. That blind spot is why
   * {@link PackageBoundaryTest} compares signatures over the whole package rather than names over
   * two classes; it is not repaired here, because a name filter cannot repair it.
   */
  @Test
  void theDeterministicMethodsStillExistUnderThatName() {
    assertThat(deterministicMethods())
        .as("a rename that drops one would leave the visibility test green on the rest")
        .hasSizeGreaterThanOrEqualTo(5);
  }

  /**
   * {@code OpaqueConfig.forTesting()} moved to {@code OpaqueTestConfigs} in {@code testFixtures}.
   *
   * <p>It builds a config with the identity KSF — no password stretching at all — and was public
   * on the production API. Test fixtures are published under a separate classifier and are not on
   * a consumer's compile classpath unless requested by name, so the boundary is now the build's
   * rather than a comment's.
   */
  @Test
  void theIdentityKsfConfigFactoriesAreNoLongerOnTheProductionApi() {
    assertThat(com.codeheadsystems.rfc.opaque.config.OpaqueConfig.class.getDeclaredMethods())
        .noneMatch(m -> m.getName().equals("forTesting"));
  }
}
