package com.codeheadsystems.hofmann.integration;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
    "hofmann.oprf-cipher-suite=RISTRETTO255_SHA512",
    "hofmann.opaque-cipher-suite=RISTRETTO255_SHA512"
})
class Ristretto255CrossClientOprfTest extends AbstractCrossClientOprfTest {

  @Override
  protected String cipherSuiteName() {
    return "RISTRETTO255_SHA512";
  }
}
