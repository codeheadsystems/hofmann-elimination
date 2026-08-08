package com.codeheadsystems.hofmann.dropwizard;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Security headers for the API docs assets.
 *
 * <p>{@link SecurityHeadersFilter} cannot do this job. It is a JAX-RS
 * {@code ContainerResponseFilter} registered through {@code environment.jersey()}, so it runs
 * inside the Jersey servlet and never sees a response produced by a sibling servlet. The API docs
 * are served by an {@code AssetServlet} registered directly on the environment, which is exactly
 * the case that filter misses — the assets went out with no {@code X-Frame-Options}, no
 * {@code Content-Security-Policy} and no {@code X-Content-Type-Options} at all. This is a
 * {@code jakarta.servlet.Filter} so that it sits in the servlet chain where those responses
 * actually pass.
 *
 * <p><strong>The CSP allows inline script and style.</strong> Swagger UI does not work without
 * them, and a policy that breaks the page would be removed by the first person to notice. What it
 * does buy is the rest of the policy: {@code default-src 'none'} means a doc bundle cannot pull
 * anything from a third-party host, {@code frame-ancestors 'none'} stops the page being framed,
 * and {@code form-action 'none'} means an injected form has nowhere to post to. The docs are
 * static assets under the deployer's control, so the injection this defends against is a
 * compromised or mistaken asset bundle rather than user input.
 *
 * <p><strong>HSTS is set only on a secure request.</strong> The JAX-RS filter sets it
 * unconditionally, which on a plaintext connection is both ignored by browsers per RFC 6797 §7.2
 * and misleading to anyone reading the response. Rather than copy that here, this matches what
 * the Spring integration does. Making the two consistent is a separate open item; this side is
 * the one that is right.
 *
 * <p>No {@code Cache-Control: no-store}: these are public static documents and there is nothing
 * to keep out of a cache. No CORS headers either, so a browser will not let another origin read
 * them cross-origin — which for documentation is the safe default rather than a limitation.
 */
public class ApiDocsSecurityHeadersFilter implements Filter {

  /** Inline script and style are required by Swagger UI; everything else is denied. */
  static final String CONTENT_SECURITY_POLICY =
      "default-src 'none'; "
          + "script-src 'self' 'unsafe-inline'; "
          + "style-src 'self' 'unsafe-inline'; "
          + "img-src 'self' data:; "
          + "font-src 'self' data:; "
          + "connect-src 'self'; "
          + "frame-ancestors 'none'; "
          + "base-uri 'none'; "
          + "form-action 'none'";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (response instanceof HttpServletResponse httpResponse) {
      // Set before the chain runs: the servlet writes and commits the response, and headers added
      // after commit are silently dropped rather than throwing.
      httpResponse.setHeader("X-Content-Type-Options", "nosniff");
      httpResponse.setHeader("X-Frame-Options", "DENY");
      httpResponse.setHeader("Referrer-Policy", "no-referrer");
      httpResponse.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
      if (request.isSecure()) {
        httpResponse.setHeader("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains");
      }
    }
    chain.doFilter(request, response);
  }
}
