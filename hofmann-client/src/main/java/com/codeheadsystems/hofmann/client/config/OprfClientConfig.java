package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;

public record OprfClientConfig(OprfCipherSuite suite) {

  public OprfClientConfig() {
    this(OprfCipherSuite.P256_SHA256);
  }
}
