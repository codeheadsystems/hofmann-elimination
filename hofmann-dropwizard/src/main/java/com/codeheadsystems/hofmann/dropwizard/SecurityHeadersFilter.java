package com.codeheadsystems.hofmann.dropwizard;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;

/**
 * JAX-RS response filter that sets standard security headers on every response.
 */
public class SecurityHeadersFilter implements ContainerResponseFilter {

  @Override
  public void filter(ContainerRequestContext requestContext,
                     ContainerResponseContext responseContext) {
    var headers = responseContext.getHeaders();
    headers.putSingle("X-Content-Type-Options", "nosniff");
    headers.putSingle("X-Frame-Options", "DENY");
    headers.putSingle("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    headers.putSingle("Cache-Control", "no-store");
  }
}
