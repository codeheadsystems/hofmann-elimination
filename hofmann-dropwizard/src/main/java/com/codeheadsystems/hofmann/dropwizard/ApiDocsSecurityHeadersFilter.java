package com.codeheadsystems.hofmann.dropwizard;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Security headers and a request-side bound for the API docs assets.
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
 * <p><strong>Headers are set twice, before and after the chain.</strong> Not belt and braces:
 * {@code AssetServlet.doGet} handles a missing asset by calling {@code response.reset()} before
 * setting 404, and {@code reset()} discards everything set beforehand. Every 404 from this mount
 * therefore went out completely bare. Widening the dispatcher set does not help, because the
 * reset happens inside the {@code REQUEST} dispatch rather than via an {@code ERROR} one — that
 * was checked rather than assumed. The pass before the chain covers the committed 200; the pass
 * after covers the reset 404.
 *
 * <p><strong>The CSP allows unpkg.com, and that is a real concession.</strong> The Swagger page
 * loads {@code swagger-ui-dist@5} from that CDN — a stylesheet and the bundle — so a policy of
 * {@code 'self'} blocked the entire UI and left only ten lines of inline glue throwing a
 * {@code ReferenceError}. An earlier version of this comment had the reasoning backwards: it
 * justified {@code 'unsafe-inline'} as what Swagger UI needs, when the inline script is the glue
 * and the CDN bundle is Swagger UI. So the policy conceded the directive that matters for XSS and
 * still broke the page. The honest fix is to vendor {@code swagger-ui-dist} into {@code docs/}
 * and then drop both the CDN and {@code 'unsafe-inline'} for script; until that happens this
 * states what the page actually needs instead of quietly shipping a policy that does not work.
 *
 * <p>What the rest of the policy still buys: {@code default-src 'none'} means nothing beyond the
 * named sources loads, {@code frame-ancestors 'none'} stops the page being framed,
 * {@code form-action 'none'} means an injected form has nowhere to post, and {@code base-uri
 * 'none'} stops a {@code <base>} tag redirecting relative URLs.
 *
 * <p><strong>HSTS follows the proxy.</strong> RFC 6797 §7.2 says a browser ignores the header
 * over plaintext, so setting it unconditionally — as the JAX-RS filter does — is misleading
 * rather than protective. But {@code isSecure()} alone is false behind a TLS-terminating proxy,
 * which is the normal deployment, so that alone would mean never setting it in production. This
 * consults {@code X-Forwarded-Proto} only when the deployment has declared the proxy trusted via
 * {@code trustForwardedHeaders}, so an untrusted client cannot forge an HSTS pin.
 *
 * <p><strong>The range cap is not decoration.</strong> {@code AssetServlet} places no bound on
 * the number of byte ranges in a {@code Range} header, and each {@code 0-} yields the whole
 * resource, so a 4.9 KB request returned 71.5 MB against the 44 KB OpenAPI spec — around
 * 14,600&times; amplification, unauthenticated. The body-size filter this mount does not have
 * would not have caught it either: the amplifier is a request header, not a body.
 */
public class ApiDocsSecurityHeadersFilter implements Filter {

  /** Inline script is the page's own glue; unpkg.com is where Swagger UI itself comes from. */
  static final String CONTENT_SECURITY_POLICY =
      "default-src 'none'; "
          + "script-src 'self' 'unsafe-inline' https://unpkg.com; "
          + "style-src 'self' 'unsafe-inline' https://unpkg.com; "
          + "img-src 'self' data:; "
          + "font-src 'self' data:; "
          + "connect-src 'self'; "
          + "frame-ancestors 'none'; "
          + "base-uri 'none'; "
          + "form-action 'none'";

  /**
   * Maximum byte ranges accepted in one request.
   *
   * <p>Well above anything a browser or a documentation tool emits — a media player seeking is
   * the usual multi-range client, and it asks for one or two — and far below the thousands it
   * takes to turn a small request into tens of megabytes of response.
   */
  static final int MAX_RANGES = 8;

  private final boolean trustForwardedHeaders;

  /**
   * Creates the filter.
   *
   * @param trustForwardedHeaders whether {@code X-Forwarded-Proto} may be believed, which is true
   *                              only when the deployment sits behind a proxy that overwrites it
   */
  public ApiDocsSecurityHeadersFilter(boolean trustForwardedHeaders) {
    this.trustForwardedHeaders = trustForwardedHeaders;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(response instanceof HttpServletResponse httpResponse)) {
      chain.doFilter(request, response);
      return;
    }
    HttpServletRequest httpRequest =
        request instanceof HttpServletRequest r ? r : null;

    if (httpRequest != null && tooManyRanges(httpRequest.getHeader("Range"))) {
      applyHeaders(httpRequest, httpResponse);
      httpResponse.sendError(HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE,
          "Too many byte ranges");
      return;
    }

    applyHeaders(httpRequest, httpResponse);
    chain.doFilter(request, response);
    // AssetServlet resets the response on a miss, discarding the headers above. Re-apply while
    // there is still a chance to; once committed, setHeader is silently ignored rather than
    // throwing, so guarding on isCommitted is what makes the second pass meaningful.
    if (!httpResponse.isCommitted()) {
      applyHeaders(httpRequest, httpResponse);
    }
  }

  private void applyHeaders(HttpServletRequest request, HttpServletResponse response) {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    if (isSecure(request)) {
      response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
  }

  private boolean isSecure(HttpServletRequest request) {
    if (request == null) {
      return false;
    }
    if (request.isSecure()) {
      return true;
    }
    return trustForwardedHeaders
        && "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
  }

  /**
   * Counts comma-separated ranges without parsing them.
   *
   * <p>Deliberately crude: the cap exists to bound work, so it must itself be cheap and must not
   * depend on agreeing with the servlet's parser about what a valid range is. A malformed header
   * that this over-counts is rejected, which is the safe direction.
   *
   * @param rangeHeader the raw Range header, or null
   * @return true if the request should be refused
   */
  static boolean tooManyRanges(String rangeHeader) {
    if (rangeHeader == null) {
      return false;
    }
    int count = 1;
    for (int i = 0; i < rangeHeader.length(); i++) {
      if (rangeHeader.charAt(i) == ',') {
        count++;
        if (count > MAX_RANGES) {
          return true;
        }
      }
    }
    return false;
  }
}
