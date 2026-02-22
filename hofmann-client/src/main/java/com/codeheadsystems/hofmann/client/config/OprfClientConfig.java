package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;

/**
 * The type Oprf client config.
 */
public record OprfClientConfig(OprfCipherSuite suite) {

  /**
   * Instantiates a new Oprf client config.
   */
  public OprfClientConfig() {
    this(OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build());
  }

}
