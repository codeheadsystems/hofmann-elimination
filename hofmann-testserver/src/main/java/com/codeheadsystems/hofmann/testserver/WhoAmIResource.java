package com.codeheadsystems.hofmann.testserver;

import com.codeheadsystems.hofmann.dropwizard.auth.HofmannPrincipal;
import io.dropwizard.auth.Auth;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Map;

/**
 * JWT-protected endpoint that returns the authenticated credential identifier.
 * Use this to verify that OPAQUE registration and authentication succeed end-to-end:
 * register a credential, authenticate to obtain a JWT, then call GET /api/whoami
 * with the token and confirm the response contains the expected identifier.
 */
@Path("/api/whoami")
@Produces(MediaType.APPLICATION_JSON)
public class WhoAmIResource {

  /**
   * Returns the credential identifier from the authenticated JWT principal.
   *
   * @param principal the principal injected by the Dropwizard auth filter
   * @return a map containing {@code credentialIdentifier}
   */
  @GET
  public Map<String, String> whoAmI(@Auth HofmannPrincipal principal) {
    return Map.of("credentialIdentifier", principal.credentialIdentifier());
  }
}
