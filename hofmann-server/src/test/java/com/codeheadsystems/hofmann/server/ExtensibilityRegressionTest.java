package com.codeheadsystems.hofmann.server;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.server.manager.JwtManager;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Regression test to ensure Server, JwtManager, and OprfServerManager remain
 * extensible (non-final classes with non-final public methods). KeyGuard depends
 * on extending these classes to delegate cryptographic operations to its sidecar.
 */
class ExtensibilityRegressionTest {

  static List<Class<?>> extensibleClasses() {
    return List.of(Server.class, JwtManager.class, OprfServerManager.class);
  }

  @ParameterizedTest
  @MethodSource("extensibleClasses")
  void classMustNotBeFinal(Class<?> clazz) {
    assertThat(Modifier.isFinal(clazz.getModifiers()))
        .as("%s must not be final — KeyGuard extends this class", clazz.getName())
        .isFalse();
  }

  @ParameterizedTest
  @MethodSource("extensibleClasses")
  void publicMethodsMustNotBeFinal(Class<?> clazz) {
    List<Method> finalMethods = Arrays.stream(clazz.getDeclaredMethods())
        .filter(m -> Modifier.isPublic(m.getModifiers()))
        .filter(m -> Modifier.isFinal(m.getModifiers()))
        .toList();

    assertThat(finalMethods)
        .as("All public methods on %s must be non-final — KeyGuard overrides them", clazz.getName())
        .isEmpty();
  }
}
