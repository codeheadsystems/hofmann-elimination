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
 * produces plausible output. In severity order:
 *
 * <ul>
 *   <li>A server reusing {@code (maskingNonce, serverAkeKeySeed, serverNonce)} makes the whole
 *       KE2 a function of the client's KE1, so a recorded exchange replays: an attacker who saw
 *       one successful authentication can authenticate again <strong>without the password</strong>.
 *   <li>Reusing {@code serverAkeKeySeed} alone destroys forward secrecy completely — one
 *       compromised ephemeral key opens every past and future session — with no functional
 *       symptom at all.
 *   <li>A client reusing a blind turns the server into a cross-account password-equality oracle:
 *       identical passwords produce identical blinded elements, so an observer learns which
 *       accounts share a password.
 *   <li>Reusing the client AKE seed makes a user's sessions linkable across logins.
 * </ul>
 *
 * <p>A javadoc line is not a control. This asserts the visibility so that widening one back is a
 * deliberate act with a failing test attached, rather than something that happens because an IDE
 * offered to make a method public to satisfy a caller in another package.
 */
class DeterministicApiVisibilityTest {

  private static List<Method> deterministicMethods() {
    return java.util.stream.Stream.of(Client.class.getDeclaredMethods(),
            Server.class.getDeclaredMethods())
        .flatMap(java.util.Arrays::stream)
        .filter(m -> m.getName().endsWith("Deterministic"))
        .toList();
  }

  @ParameterizedTest
  @MethodSource("deterministicMethods")
  void isNotPublic(Method method) {
    assertThat(Modifier.isPublic(method.getModifiers()))
        .as("%s.%s must not be reachable from outside this package",
            method.getDeclaringClass().getSimpleName(), method.getName())
        .isFalse();
  }

  /**
   * Guards the guard: if the naming convention changed, the parameterised test above would pass
   * with an empty argument list and assert nothing.
   */
  @Test
  void theDeterministicMethodsStillExistUnderThatName() {
    assertThat(deterministicMethods())
        .as("an empty list would make the visibility test vacuous")
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
