package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;

public record OprfConfig(OprfCipherSuite suite) {

  public OprfConfig() {
    this(OprfCipherSuite.P256_SHA256);
  }
}
