package com.codeheadsystems.hofmann.integration;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
    "hofmann.oprf-cipher-suite=P384_SHA384",
    "hofmann.opaque-cipher-suite=P384_SHA384"
})
class P384OpaqueIntegrationTest extends AbstractOpaqueIntegrationTest {

  @Override
  protected String cipherSuiteName() {
    return "P384_SHA384";
  }
}
