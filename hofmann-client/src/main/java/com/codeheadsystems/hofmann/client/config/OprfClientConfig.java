package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;

public record OprfClientConfig(OprfCipherSuite suite) {

  public OprfClientConfig() {
    this(OprfCipherSuite.builder().withSuite(OprfCipherSuite.Builder.SUITE.P256_SHA256).build());
  }

  /**
   * Creates a config using the named cipher suite.  Accepted names: {@code "P256_SHA256"},
   * {@code "P384_SHA384"}, {@code "P521_SHA512"}.
   *
   * @throws IllegalArgumentException for unrecognised names
   */
  public static OprfClientConfig fromName(String cipherSuiteName) {
    return new OprfClientConfig(OprfCipherSuite.fromName(cipherSuiteName));
  }
}
