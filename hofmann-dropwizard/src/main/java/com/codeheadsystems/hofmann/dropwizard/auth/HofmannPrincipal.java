package com.codeheadsystems.hofmann.dropwizard.auth;

import java.security.Principal;

/**
 * Principal representing an authenticated Hofmann user.
 *
 * @param credentialIdentifier base64-encoded credential identifier from the JWT subject
 * @param jti                  JWT ID for session management
 */
public record HofmannPrincipal(String credentialIdentifier, String jti) implements Principal {

  @Override
  public String getName() {
    return credentialIdentifier;
  }
}
