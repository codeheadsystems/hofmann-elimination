package com.codeheadsystems.hofmann.client.model;

import java.net.URI;

/**
 * Network connection details for a single OPRF server.
 *
 * <p>Two conventions for {@code endpoint} exist in the wild and both work. It may be the server
 * root ({@code http://host:8080}), which is what {@code HofmannOpaqueAccessor} has always assumed,
 * or the OPRF base itself ({@code http://host:8080/oprf}), which is what every caller in this
 * repository configures. {@code HofmannOprfAccessor} infers which by looking for a trailing
 * {@code /oprf} and appends the sub-path accordingly, so the same value serves
 * {@code /oprf/config}, {@code /oprf}, {@code /oprf/verifiable} and
 * {@code /oprf/partially-oblivious}.
 *
 * @param endpoint     the server root or the OPRF base, as above
 * @param oprfBasePath the absolute path the OPRF resource is mounted at, overriding the inference.
 *                     Null in the ordinary case. Needed only by a deployment that mounts the
 *                     resource somewhere whose path does not end in {@code /oprf}, where the
 *                     inference would append a second segment
 */
public record ServerConnectionInfo(URI endpoint, String oprfBasePath) {

  /**
   * The ordinary form, inferring the OPRF base path from the endpoint.
   *
   * @param endpoint the server root or the OPRF base
   */
  public ServerConnectionInfo(final URI endpoint) {
    this(endpoint, null);
  }
}
