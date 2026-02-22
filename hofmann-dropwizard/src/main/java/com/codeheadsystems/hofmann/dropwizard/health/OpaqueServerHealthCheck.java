package com.codeheadsystems.hofmann.dropwizard.health;

import com.codahale.metrics.health.HealthCheck;
import com.codeheadsystems.rfc.opaque.Server;

/**
 * Health check that verifies the OPAQUE server is initialized with a valid public key.
 */
public class OpaqueServerHealthCheck extends HealthCheck {

  private final Server server;

  /**
   * Instantiates a new Opaque server health check.
   *
   * @param server the server
   */
  public OpaqueServerHealthCheck(Server server) {
    this.server = server;
  }

  @Override
  protected Result check() {
    byte[] pk = server.getServerPublicKey();
    if (pk == null || pk.length == 0) {
      return Result.unhealthy("Server public key is absent");
    }
    // Compressed SEC1 point: 33 bytes for P-256, 49 bytes for P-384, 67 bytes for P-521.
    // First byte must be 0x02 or 0x03.
    if (pk[0] != 0x02 && pk[0] != 0x03) {
      return Result.unhealthy("Server public key does not appear to be a compressed SEC1 point");
    }
    return Result.healthy("public key length=%d", pk.length);
  }
}
