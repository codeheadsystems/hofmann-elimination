package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Every request model that carries a credential identifier must expose one canonical base64
 * spelling, because the server keys the credential store on the decoded bytes but keys the
 * session index, the JWT subject, and every rate-limiter bucket on the string.
 *
 * <p>{@link Base64.Decoder} ignores both padding and the unused trailing bits of the final
 * character, so without normalization one account has up to 32 accepted spellings — which
 * makes session revocation miss and multiplies the rate-limit budget.
 */
class CredentialIdentifierCanonicalizationTest {

  /** All six spellings decode to "alice"; only the first is canonical. */
  private static final String CANONICAL = "YWxpY2U=";
  private static final List<String> ALIASES =
      List.of("YWxpY2U=", "YWxpY2U", "YWxpY2V", "YWxpY2V=", "YWxpY2W=", "YWxpY2X=");

  /** Each model, reduced to "given a base64 string, what identifier string do you report?". */
  static Stream<Arguments> models() {
    return Stream.of(
        Arguments.of("AuthStartRequest",
            (Function<String, String>) s ->
                new AuthStartRequest(s, "AA==", "AA==", "AA==").credentialIdentifierBase64()),
        Arguments.of("RegistrationStartRequest",
            (Function<String, String>) s ->
                new RegistrationStartRequest(s, "AA==").credentialIdentifierBase64()),
        Arguments.of("RegistrationFinishRequest",
            (Function<String, String>) s ->
                new RegistrationFinishRequest(s, "AA==", "AA==", "AA==", "AA==")
                    .credentialIdentifierBase64()),
        Arguments.of("RegistrationDeleteRequest",
            (Function<String, String>) s ->
                new RegistrationDeleteRequest(s).credentialIdentifierBase64()),
        Arguments.of("RecoveryStartRequest",
            (Function<String, String>) s ->
                new RecoveryStartRequest(s).credentialIdentifierBase64()),
        Arguments.of("RecoveryVerifyRequest",
            (Function<String, String>) s ->
                new RecoveryVerifyRequest(s, "123456").credentialIdentifierBase64()));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("models")
  void allAliasesCollapseToOneSpelling(String name, Function<String, String> accessor) {
    Set<String> reported = new LinkedHashSet<>();
    for (String alias : ALIASES) {
      reported.add(accessor.apply(alias));
    }
    assertThat(reported)
        .as("%s must report a single spelling for all %d aliases of the same identifier",
            name, ALIASES.size())
        .containsExactly(CANONICAL);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("models")
  void canonicalSpellingIsUnchanged(String name, Function<String, String> accessor) {
    assertThat(accessor.apply(CANONICAL)).isEqualTo(CANONICAL);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("models")
  void invalidBase64IsRejected(String name, Function<String, String> accessor) {
    assertThatThrownBy(() -> accessor.apply("!!!not base64!!!"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * Null and blank pass through untouched so the existing per-field "Missing required field"
   * validation still produces its own message rather than being pre-empted here.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("models")
  void nullAndBlankPassThrough(String name, Function<String, String> accessor) {
    assertThat(accessor.apply(null)).isNull();
    assertThat(accessor.apply("")).isEmpty();
  }

  /** Canonicalization must never change which account is addressed. */
  @ParameterizedTest
  @ValueSource(strings = {"a", "ab", "abc", "abcd", "abcde", "abcdef", "alice@example.com"})
  void canonicalizationPreservesTheDecodedBytes(String identifier) {
    byte[] raw = identifier.getBytes(StandardCharsets.UTF_8);
    String encoded = Base64.getEncoder().encodeToString(raw);

    String canonical = new RecoveryStartRequest(encoded).credentialIdentifierBase64();

    assertThat(Base64.getDecoder().decode(canonical)).isEqualTo(raw);
  }

  /**
   * Pins the premise: the JDK decoder really does accept all six spellings. If a future JDK
   * tightened this, the vulnerability would be gone and this test would tell us why the
   * canonicalization is no longer load-bearing.
   */
  @Test
  void jdkDecoderAcceptsEveryAlias() {
    for (String alias : ALIASES) {
      assertThat(new String(Base64.getDecoder().decode(alias), StandardCharsets.UTF_8))
          .as("alias %s", alias)
          .isEqualTo("alice");
    }
  }

  /**
   * Alias count is a function of length mod 3: 1 for len%3==0, 8 for len%3==2, 32 for
   * len%3==1. Documents why roughly two thirds of a real user base was affected.
   */
  @Test
  void aliasCountDependsOnIdentifierLength() {
    assertThat(countAliases("abcdef")).as("len%%3==0").isEqualTo(1);
    assertThat(countAliases("alice")).as("len%%3==2").isEqualTo(8);
    assertThat(countAliases("abcd")).as("len%%3==1").isEqualTo(32);
  }

  private static int countAliases(String identifier) {
    byte[] raw = identifier.getBytes(StandardCharsets.UTF_8);
    String canonical = Base64.getEncoder().encodeToString(raw);
    String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Set<String> aliases = new LinkedHashSet<>();
    String unpadded = canonical.replace("=", "");
    int lastIndex = unpadded.length() - 1;
    for (char c : alphabet.toCharArray()) {
      String candidate = unpadded.substring(0, lastIndex) + c;
      for (String variant : List.of(candidate, candidate + "=", candidate + "==")) {
        try {
          if (java.util.Arrays.equals(Base64.getDecoder().decode(variant), raw)) {
            aliases.add(variant);
          }
        } catch (IllegalArgumentException ignored) {
          // not a valid encoding, not an alias
        }
      }
    }
    return aliases.size();
  }
}
