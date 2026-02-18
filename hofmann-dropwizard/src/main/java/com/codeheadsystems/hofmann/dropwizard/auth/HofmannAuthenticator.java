package com.codeheadsystems.hofmann.dropwizard.auth;

import com.codeheadsystems.hofmann.server.auth.JwtManager;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import java.util.Optional;

/**
 * Dropwizard {@link Authenticator} that validates JWT bearer tokens using {@link JwtManager}.
 */
public class HofmannAuthenticator implements Authenticator<String, HofmannPrincipal> {

  private final JwtManager jwtManager;

  public HofmannAuthenticator(JwtManager jwtManager) {
    this.jwtManager = jwtManager;
  }

  @Override
  public Optional<HofmannPrincipal> authenticate(String token) throws AuthenticationException {
    return jwtManager.verify(token)
        .map(result -> new HofmannPrincipal(result.subject(), result.jti()));
  }
}
