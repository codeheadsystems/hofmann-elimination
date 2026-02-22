package com.codeheadsystems.hofmann.springboot.security;

import java.security.Principal;

/**
 * The type Hofmann principal.
 */
public record HofmannPrincipal(String credentialIdentifier, String jti) implements Principal {

  @Override
  public String getName() {
    return credentialIdentifier;
  }
}
