package com.codeheadsystems.hofmann.springboot.security;

import java.security.Principal;

public record HofmannPrincipal(String credentialIdentifier, String jti) implements Principal {

  @Override
  public String getName() {
    return credentialIdentifier;
  }
}
