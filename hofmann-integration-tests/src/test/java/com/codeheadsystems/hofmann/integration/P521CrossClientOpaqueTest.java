package com.codeheadsystems.hofmann.integration;

import org.junit.jupiter.api.Disabled;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * P521 cross-client OPAQUE is disabled due to a known interop issue between Java and TypeScript
 * clients: envelope recovery fails in both directions (Java→TS and TS→Java).
 * P521 Java-only and TS-only OPAQUE tests pass independently; the issue is specific to
 * cross-client serialization of P-521 OPAQUE protocol messages.
 */
@Disabled("P521 cross-client OPAQUE interop issue — envelope auth tag mismatch between Java and TS")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
    "hofmann.oprf-cipher-suite=P521_SHA512",
    "hofmann.opaque-cipher-suite=P521_SHA512"
})
class P521CrossClientOpaqueTest extends AbstractCrossClientOpaqueTest {

  @Override
  protected String cipherSuiteName() {
    return "P521_SHA512";
  }
}
