package com.codeheadsystems.rfc.opaque;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Pins the entire public surface of {@code com.codeheadsystems.rfc.opaque}, by signature.
 *
 * <p>{@link DeterministicApiVisibilityTest} asserts that the five {@code *Deterministic} methods
 * are not public. That was worth having and it was never a boundary, for a reason it stated
 * itself: the filter is <em>name-based</em>. The capabilities it names were also reachable through
 * {@code ...opaque.internal}, where {@code OpaqueAke.generateKE2} took {@code maskingNonce} and
 * {@code serverAkeKeySeed} as ordinary parameters and so was invisible to a name filter by
 * construction. A reviewer rebuilt all five from another package using public API and no
 * reflection.
 *
 * <p>That package no longer exists — {@code OpaqueOprf}, {@code OpaqueCredentials},
 * {@code OpaqueEnvelope} and {@code OpaqueAke} are package-private here — and this test is what
 * keeps it from growing back. It enumerates the package off disk rather than consulting a list of
 * class names, so a new class is covered the moment it is written, and it compares whole
 * signatures rather than method names, so the {@code generateKE2} shape is exactly as visible to
 * it as the {@code generateKE2Deterministic} one.
 *
 * <p><strong>What this cannot assert.</strong> The jar seals this package, which is what stops a
 * class declared into it from another jar reaching these methods, and sealing is only enforced
 * when the classes are loaded from that jar. This test runs against a classes directory, so there
 * is nothing here to observe. That assertion lives in the build as
 * {@code :hofmann-rfc:verifyOpaquePackageSealed}, which runs as part of {@code check} and — note —
 * checks it by loading a second code source for this package in front of the built jar and
 * requiring the refusal, not by reading the manifest string.
 *
 * <p><strong>What neither asserts, because it is not true.</strong> None of this makes the
 * deterministic behaviours unreachable. A rigged {@code SecureRandom} handed to
 * {@code OprfCipherSuite.Builder.withRandom} fixes every nonce in the protocol at once; see
 * {@code Client}'s section comment and {@code OprfCipherSuite.withRandom}, where that residual is
 * accepted and argued. What is being defended here is the accident, not the capability.
 */
class PackageBoundaryTest {

  private static final String PACKAGE = "com.codeheadsystems.rfc.opaque";

  /**
   * The complete public and protected API of this package.
   *
   * <p>Protected counts as public here: {@code Client} and {@code Server} are both non-final, so a
   * consumer subclass in any package reaches a protected member.
   *
   * <p>Fields count too, and there are none — {@code Client} and {@code Server} declare no public
   * or protected field, so nothing below has the {@code Type Class.name} shape. Enumerating them
   * anyway is not ceremony: a reviewer added {@code public static final BigInteger RFC_TEST_BLIND}
   * to {@code Client} against an earlier draft of this test that read only methods and
   * constructors, and the build stayed green. A published blind constant is the single worst thing
   * that can appear on this API — see {@link DeterministicApiVisibilityTest} — and it is a field.
   *
   * <p>Adding a line to this list is the deliberate act. Before you do, the thing to check is not
   * whether the member is <em>named</em> like a test hook but whether it lets a caller supply, or
   * simply read, the blind, an envelope nonce, a masking nonce, a server AKE seed or a server
   * nonce.
   */
  private static final List<String> PINNED_API = List.of(
      "Client(OpaqueConfig)",
      "Client.createRegistrationRequest(byte[])",
      "Client.finalizeRegistration(ClientRegistrationState,RegistrationResponse,byte[],byte[])",
      "Client.generateKE1(byte[])",
      "Client.generateKE3(ClientAuthState,byte[],byte[],KE2)",
      "Server(byte[],byte[],byte[],OpaqueConfig)",
      "Server.createRegistrationResponse(RegistrationRequest,byte[])",
      "Server.generate(OpaqueConfig)",
      "Server.generateFakeKE2(KE1,byte[],byte[],byte[])",
      "Server.generateKE2(byte[],RegistrationRecord,byte[],KE1,byte[])",
      "Server.generateKE2ForRecordOrFake(byte[],RegistrationRecord,byte[],KE1,byte[])",
      "Server.getServerPublicKey()",
      "Server.serverFinish(ServerAuthState,KE3)",
      "Server.validateRegistrationRecord(RegistrationRecord)");

  /**
   * {@code Client} and {@code Server} are the only types a consumer can name.
   *
   * <p>Enumerated from the compiled output rather than from a hard-coded list, so a class added to
   * this package tomorrow is covered without anyone remembering to add it here. Nested types count
   * — {@code OpaqueEnvelope.StoreResult} and {@code RecoverResult} were public records until the
   * internal package was folded in, and a public record inside a package-private class is still a
   * type whose accessors a consumer could reach if the enclosing class were ever widened.
   */
  @Test
  void onlyClientAndServerArePublicTypes() {
    assertThat(typesInPackage().filter(c -> Modifier.isPublic(c.getModifiers())).map(Class::getSimpleName).sorted())
        .as("a public type here is reachable by any consumer; the protocol internals must not be")
        .containsExactly("Client", "Server");
  }

  /**
   * The public surface is exactly {@link #PINNED_API}, compared by signature.
   *
   * <p>Both directions matter. An addition is a capability nobody reviewed. A removal is a
   * breaking change to consumers, which should also not happen by accident.
   */
  @Test
  void thePublicSurfaceIsExactlyWhatIsPinned() {
    List<String> actual = typesInPackage()
        .filter(c -> Modifier.isPublic(c.getModifiers()))
        .flatMap(c -> Stream.concat(
            Stream.of(c.getDeclaredConstructors(), c.getDeclaredMethods())
                .flatMap(Stream::of)
                .filter(e -> (e.getModifiers() & (Modifier.PUBLIC | Modifier.PROTECTED)) != 0)
                .filter(e -> !e.isSynthetic())
                .map(PackageBoundaryTest::signature),
            Stream.of(c.getDeclaredFields())
                .filter(f -> (f.getModifiers() & (Modifier.PUBLIC | Modifier.PROTECTED)) != 0)
                .filter(f -> !f.isSynthetic())
                .map(PackageBoundaryTest::signature)))
        .sorted()
        .toList();

    assertThat(actual)
        .as("the public API of %s changed; see this test's javadoc before widening the list", PACKAGE)
        .containsExactlyElementsOf(PINNED_API.stream().sorted().toList());
  }

  /** {@code Type Class.name} — deliberately unlike the method shape, so a mix-up cannot pass. */
  private static String signature(Field f) {
    return f.getType().getSimpleName() + " "
        + f.getDeclaringClass().getSimpleName() + "." + f.getName();
  }

  /** {@code Simple(ParamTypes)} for a method, {@code Simple(ParamTypes)} for a constructor. */
  private static String signature(Executable e) {
    String params = Stream.of(e.getParameterTypes())
        .map(Class::getSimpleName)
        .collect(Collectors.joining(","));
    String name = e instanceof Constructor<?>
        ? e.getDeclaringClass().getSimpleName()
        : e.getDeclaringClass().getSimpleName() + "." + e.getName();
    return name + "(" + params + ")";
  }

  /**
   * Every type compiled into this package, nested types included.
   *
   * <p>Reads the code source rather than the classpath at large, so it sees exactly what ships.
   * Handles both layouts: a directory under Gradle, a jar if this is ever run against the
   * artifact.
   */
  private static Stream<Class<?>> typesInPackage() {
    URI location;
    try {
      location = Client.class.getProtectionDomain().getCodeSource().getLocation().toURI();
    } catch (Exception e) {
      throw new IllegalStateException("cannot locate the code source for " + PACKAGE, e);
    }
    Path root = location.getPath().endsWith(".jar")
        ? jarRoot(location)
        : Path.of(location);
    Path packageDir = root.resolve(PACKAGE.replace('.', '/'));
    try (Stream<Path> entries = Files.list(packageDir)) {
      List<Class<?>> found = entries
          .map(p -> p.getFileName().toString())
          .filter(n -> n.endsWith(".class"))
          // The file name is already the binary name's last segment, nested types included:
          // OpaqueEnvelope$StoreResult.class is exactly what Class.forName wants after the package.
          .map(n -> n.substring(0, n.length() - ".class".length()))
          .<Class<?>>map(n -> loadClass(PACKAGE + "." + n))
          .toList();
      return found.stream();
    } catch (IOException e) {
      throw new UncheckedIOException("cannot list " + packageDir, e);
    }
  }

  private static Path jarRoot(URI jar) {
    try {
      return java.nio.file.FileSystems
          .newFileSystem(URI.create("jar:" + jar), java.util.Map.<String, Object>of())
          .getPath("/");
    } catch (IOException e) {
      throw new UncheckedIOException("cannot open " + jar, e);
    }
  }

  private static Class<?> loadClass(String name) {
    try {
      return Class.forName(name, false, PackageBoundaryTest.class.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }
}
