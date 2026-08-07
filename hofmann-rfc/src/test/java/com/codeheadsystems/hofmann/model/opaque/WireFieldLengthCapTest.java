package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Pins the field-length cap on every request model.
 *
 * <p>{@code RegistrationStartRequest} and {@code AuthStartRequest} enforced it and named the risk
 * in a comment; the other five copied the decode helper without the check. The one that mattered
 * most was {@code registrationFinish} — unauthenticated, and the only path whose output is written
 * to durable storage. All seven now share {@link WireFields}, so the cap cannot be present on some
 * paths and absent on others.
 */
class WireFieldLengthCapTest {

  /** One character past the cap, in valid base64 alphabet so length is what rejects it. */
  private static String oversized() {
    return "A".repeat(WireFields.MAX_ENCODED_FIELD_LENGTH + 1);
  }

  private interface Executable {
    void run();
  }

  static Stream<Arguments> requestModels() {
    String big = oversized();
    return Stream.of(
        Arguments.of("RegistrationStartRequest.credentialIdentifier",
            (Executable) () -> new RegistrationStartRequest(big, "AAAA").credentialIdentifier()),
        Arguments.of("RegistrationStartRequest.blindedElement",
            (Executable) () -> new RegistrationStartRequest("AAAA", big).registrationRequest()),
        Arguments.of("RegistrationFinishRequest.credentialIdentifier",
            (Executable) () -> new RegistrationFinishRequest(big, "AAAA", "AAAA", "AAAA", "AAAA")
                .credentialIdentifier()),
        Arguments.of("RegistrationFinishRequest.clientPublicKey",
            (Executable) () -> new RegistrationFinishRequest("AAAA", big, "AAAA", "AAAA", "AAAA")
                .registrationRecord()),
        Arguments.of("RegistrationFinishRequest.maskingKey",
            (Executable) () -> new RegistrationFinishRequest("AAAA", "AAAA", big, "AAAA", "AAAA")
                .registrationRecord()),
        Arguments.of("RegistrationFinishRequest.envelopeNonce",
            (Executable) () -> new RegistrationFinishRequest("AAAA", "AAAA", "AAAA", big, "AAAA")
                .registrationRecord()),
        Arguments.of("RegistrationFinishRequest.authTag",
            (Executable) () -> new RegistrationFinishRequest("AAAA", "AAAA", "AAAA", "AAAA", big)
                .registrationRecord()),
        Arguments.of("RegistrationDeleteRequest.credentialIdentifier",
            (Executable) () -> new RegistrationDeleteRequest(big).credentialIdentifier()),
        Arguments.of("RecoveryStartRequest.credentialIdentifier",
            (Executable) () -> new RecoveryStartRequest(big).credentialIdentifier()),
        Arguments.of("RecoveryVerifyRequest.credentialIdentifier",
            (Executable) () -> new RecoveryVerifyRequest(big, "1234").credentialIdentifier()),
        Arguments.of("RecoveryVerifyRequest.challengeResponse",
            (Executable) () -> new RecoveryVerifyRequest("AAAA", big)
                .validatedChallengeResponse()),
        Arguments.of("AuthStartRequest.credentialIdentifier",
            (Executable) () -> new AuthStartRequest(big, "AAAA", "AAAA", "AAAA")
                .credentialIdentifier()),
        Arguments.of("AuthStartRequest.blindedElement",
            (Executable) () -> new AuthStartRequest("AAAA", big, "AAAA", "AAAA").ke1()),
        Arguments.of("AuthFinishRequest.clientMac",
            (Executable) () -> new AuthFinishRequest("token", big).ke3()),
        Arguments.of("AuthFinishRequest.sessionToken",
            (Executable) () -> new AuthFinishRequest(big, "AAAA").sessionToken()));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("requestModels")
  void oversizedField_isRejected(String name, Executable call) {
    assertThatThrownBy(call::run)
        .as("%s must enforce the field-length cap", name)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Field too large");
  }

  @Test
  void credentialIdentifierCanonicalization_boundsBeforeDecoding() {
    // CredentialIdentifiers.canonicalize runs ahead of the models' decode, so it carries the
    // bound itself rather than letting an oversized value be decoded and re-encoded first.
    assertThatThrownBy(() -> new RegistrationStartRequest(oversized(), "AAAA")
        .credentialIdentifierBase64())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Field too large");
  }
}
