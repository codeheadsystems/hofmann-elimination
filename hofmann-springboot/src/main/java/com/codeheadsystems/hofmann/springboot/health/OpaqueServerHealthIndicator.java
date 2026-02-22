package com.codeheadsystems.hofmann.springboot.health;

import com.codeheadsystems.rfc.opaque.Server;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
public class OpaqueServerHealthIndicator implements HealthIndicator {

  private final Server server;

  public OpaqueServerHealthIndicator(Server server) {
    this.server = server;
  }

  @Override
  public Health health() {
    byte[] pk = server.getServerPublicKey();
    if (pk == null || pk.length == 0) {
      return Health.down().withDetail("reason", "Server public key is absent").build();
    }
    if (pk[0] != 0x02 && pk[0] != 0x03) {
      return Health.down()
          .withDetail("reason", "Server public key does not appear to be a compressed SEC1 point")
          .build();
    }
    return Health.up().withDetail("publicKeyLength", pk.length).build();
  }
}
