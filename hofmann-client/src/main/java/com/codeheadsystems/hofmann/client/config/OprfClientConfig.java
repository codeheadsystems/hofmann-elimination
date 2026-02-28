package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
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

  /**
   * Creates an {@link OprfClientConfig} from a server-supplied config response.
   *
   * @param cfg the server config response from GET /oprf/config
   * @return the oprf client config
   */
  public static OprfClientConfig fromServerConfig(OprfClientConfigResponse cfg) {
    return new OprfClientConfig(OprfCipherSuite.builder().withSuite(cfg.cipherSuite()).build());
  }

}
