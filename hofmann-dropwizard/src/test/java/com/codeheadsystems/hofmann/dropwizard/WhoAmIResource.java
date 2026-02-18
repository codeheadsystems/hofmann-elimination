package com.codeheadsystems.hofmann.dropwizard;

import com.codeheadsystems.hofmann.dropwizard.auth.HofmannPrincipal;
import io.dropwizard.auth.Auth;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Map;

/**
 * Test-only protected endpoint that returns the authenticated user's credential identifier.
 * Demonstrates how consumers can protect their own routes using {@code @Auth HofmannPrincipal}.
 */
@Path("/api/whoami")
@Produces(MediaType.APPLICATION_JSON)
public class WhoAmIResource {

  @GET
  public Map<String, String> whoAmI(@Auth HofmannPrincipal principal) {
    return Map.of("credentialIdentifier", principal.credentialIdentifier());
  }
}
