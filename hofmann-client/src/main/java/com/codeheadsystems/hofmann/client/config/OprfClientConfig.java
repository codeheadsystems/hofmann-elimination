package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;

/**
 * Client-side OPRF configuration: the cipher suite the client will use when blinding requests and
 * unblinding responses. It must agree with the server's suite, which is why
 * {@link #fromServerConfig} exists.
 *
 * @param suite the OPRF cipher suite to use
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
