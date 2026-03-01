package com.codeheadsystems.hofmann.integration;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

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
