package com.codeheadsystems.hofmann.client.model;

import java.net.URI;

/**
 * Network connection details for a single OPRF server.
 *
 * @param endpoint The fully-qualified URI of the server's OPRF endpoint (e.g. http://host:8080/oprf).
 */
public record ServerConnectionInfo(URI endpoint) {
}
