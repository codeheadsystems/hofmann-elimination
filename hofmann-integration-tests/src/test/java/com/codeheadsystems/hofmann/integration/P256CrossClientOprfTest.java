package com.codeheadsystems.hofmann.integration;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
    "hofmann.oprf-cipher-suite=P256_SHA256",
    "hofmann.opaque-cipher-suite=P256_SHA256"
})
class P256CrossClientOprfTest extends AbstractCrossClientOprfTest {

  @Override
  protected String cipherSuiteName() {
    return "P256_SHA256";
  }
}
