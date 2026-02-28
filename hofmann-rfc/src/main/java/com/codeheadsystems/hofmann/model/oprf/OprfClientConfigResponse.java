package com.codeheadsystems.hofmann.model.oprf;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Server response to GET /oprf/config — the cipher suite the server is using.
 *
 * @param cipherSuite the OPRF cipher suite name (e.g. {@code "P256_SHA256"})
 */
public record OprfClientConfigResponse(
    @JsonProperty("cipherSuite") String cipherSuite) {}
