package com.codeheadsystems.hofmann.springboot.security;

import java.security.Principal;

/**
 * The authenticated identity established by a verified Hofmann JWT, published into the Spring
 * Security context by {@code JwtAuthenticationFilter}.
 *
 * @param credentialIdentifier the base64-encoded credential identifier the token was issued for;
 *                             also what {@link #getName()} returns
 * @param jti                  the token's JWT ID, the handle
 *                             {@code JwtManager.revoke(String)} takes to revoke this session
 */
public record HofmannPrincipal(String credentialIdentifier, String jti) implements Principal {

  @Override
  public String getName() {
    return credentialIdentifier;
  }
}
