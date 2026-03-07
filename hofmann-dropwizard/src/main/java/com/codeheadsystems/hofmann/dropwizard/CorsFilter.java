package com.codeheadsystems.hofmann.dropwizard;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import java.util.Set;

/**
 * JAX-RS response filter that sets CORS headers based on a configured set of allowed origins.
 * <p>
 * When the set is empty (the default), no CORS headers are added and all cross-origin
 * requests are effectively blocked by the browser's same-origin policy.
 */
public class CorsFilter implements ContainerResponseFilter {

  private final Set<String> allowedOrigins;

  /**
   * Instantiates a new Cors filter.
   *
   * @param allowedOrigins the allowed origins (empty set blocks all cross-origin requests)
   */
  public CorsFilter(Set<String> allowedOrigins) {
    this.allowedOrigins = Set.copyOf(allowedOrigins);
  }

  @Override
  public void filter(ContainerRequestContext requestContext,
                     ContainerResponseContext responseContext) {
    if (allowedOrigins.isEmpty()) {
      return;
    }
    String origin = requestContext.getHeaderString("Origin");
    if (origin != null && allowedOrigins.contains(origin)) {
      var headers = responseContext.getHeaders();
      headers.putSingle("Access-Control-Allow-Origin", origin);
      headers.putSingle("Access-Control-Allow-Methods", "GET, POST, DELETE");
      headers.putSingle("Access-Control-Allow-Headers", "Content-Type, Authorization");
      headers.putSingle("Vary", "Origin");
    }
  }
}
