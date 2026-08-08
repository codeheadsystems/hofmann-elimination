package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * The API docs servlet is opt-in, and when opted into it sits behind security headers.
 *
 * <p>Previously it was registered unconditionally on every consumer's application. A bundle
 * installs into somebody else's server, so that claimed {@code /api-docs} and {@code /api-docs/*}
 * whether the consumer wanted docs or not, and collided with any mapping they already had there.
 * It was also an {@code AssetServlet} rather than a JAX-RS resource, which meant every filter the
 * bundle registers through {@code environment.jersey()} — the security headers, CORS, the
 * body-size limit — skipped it entirely.
 *
 * <p><strong>The assets are real, which is worth stating because I first assumed they were
 * not.</strong> {@code hofmann-dropwizard} ships no {@code src/main/resources}, so I took the
 * exposure to be hypothetical — but {@code hofmann-server}'s {@code processResources} copies
 * {@code docs/*.html} and {@code docs/*.yaml} into {@code META-INF/resources/api-docs}, and this
 * module depends on it. A request against the running server returns 33 KB of HTML. Every
 * consumer of this bundle was serving that page, unasked, with no security headers on it. Probed
 * rather than reasoned about, and the probe contradicted the reasoning.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class ApiDocsRegistrationTest {

  private static HttpResponse<String> get(String url) throws Exception {
    return HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI.create(url)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  /** Path normalisation is pure, so it is checked directly rather than through a server. */
  @Nested
  class PathNormalization {

    @Test
    void addsALeadingSlashAndStripsTrailingOnes() {
      assertThat(HofmannBundle.normalizeApiDocsPath("api-docs")).isEqualTo("/api-docs");
      assertThat(HofmannBundle.normalizeApiDocsPath("/api-docs/")).isEqualTo("/api-docs");
      assertThat(HofmannBundle.normalizeApiDocsPath("/api-docs///")).isEqualTo("/api-docs");
      assertThat(HofmannBundle.normalizeApiDocsPath("  /docs/api  ")).isEqualTo("/docs/api");
    }

    /**
     * A servlet mapping is matched literally, so a path that normalises to the root would take
     * {@code /*} and shadow the API itself. Failing at startup is the only safe answer — the
     * alternative is a server that boots and then serves documentation where OPAQUE should be.
     */
    @Test
    void refusesAPathThatWouldShadowTheWholeApplication() {
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath("/"))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath(""))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath(null))
          .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * The root was the only case the earlier validator caught, and it was not the dangerous one.
     *
     * <p>A servlet mapping of {@code /opaque/*} takes precedence over Jersey's {@code /*}, so
     * {@code apiDocsPath: "/opaque"} started cleanly and replaced every authentication endpoint
     * with static documentation — {@code /opaque/config} 404, {@code /opaque/register/start} 404,
     * {@code /opaque/index.html} 200 with 33 KB of HTML — while {@code /oprf} kept working, which
     * makes it about as hard to diagnose as a failure gets. Demonstrated by a reviewer against a
     * running server; the javadoc had claimed to prevent exactly this.
     */
    @Test
    void refusesAPathThatWouldShadowTheApiEndpoints() {
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath("/opaque"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("would replace the API");
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath("/oprf"))
          .isInstanceOf(IllegalArgumentException.class);
      // Sub-paths are the same problem: /opaque/* is the mapping either way.
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath("/opaque/docs"))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath("/OPAQUE"))
          .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * Everything here was previously accepted, and every one of them failed silently rather than
     * loudly: a wildcard produced a mapping the container rejected only by luck, a query string
     * left the docs reachable at a percent-encoded path nobody would guess, and a newline in a
     * YAML value went straight into a servlet mapping.
     */
    @Test
    void refusesAMalformedPath() {
      for (String bad : new String[]{"/*", "*", "/api-docs?x=1", "/a b", "//api-docs",
          "/api-docs/../..", "/api\ndocs", "/api-docs#frag", "/api%2Fdocs"}) {
        assertThatThrownBy(() -> HofmannBundle.normalizeApiDocsPath(bad))
            .as("should reject %s", bad)
            .isInstanceOf(IllegalArgumentException.class);
      }
    }
  }

  /** The range cap is pure, so it is checked directly. */
  @Nested
  class RangeCounting {

    /**
     * {@code AssetServlet} puts no bound on the number of byte ranges and {@code 0-} yields the
     * whole resource each time, so a 4.9 KB request returned 71.5 MB against the 44 KB OpenAPI
     * spec — around 14,600&times; amplification, unauthenticated. Measured by a reviewer.
     *
     * <p>Worth noting what this corrects: the commit that added this mount argued no request-side
     * limit was needed because the servlet never reads a body. True, and beside the point — the
     * amplifier is a request header.
     */
    @Test
    void rejectsOnlyImplausibleRangeCounts() {
      assertThat(ApiDocsSecurityHeadersFilter.tooManyRanges(null)).isFalse();
      assertThat(ApiDocsSecurityHeadersFilter.tooManyRanges("bytes=0-1023")).isFalse();
      assertThat(ApiDocsSecurityHeadersFilter.tooManyRanges("bytes=0-99,200-299")).isFalse();
      assertThat(ApiDocsSecurityHeadersFilter.tooManyRanges("bytes=" + "0-,".repeat(7) + "0-"))
          .as("8 ranges is the cap and must still be served")
          .isFalse();
      assertThat(ApiDocsSecurityHeadersFilter.tooManyRanges("bytes=" + "0-,".repeat(8) + "0-"))
          .isTrue();
      assertThat(ApiDocsSecurityHeadersFilter.tooManyRanges("bytes=" + "0-,".repeat(2000) + "0-"))
          .isTrue();
    }
  }

  /** Default configuration: no {@code serveApiDocs} key at all. */
  @Nested
  @ExtendWith(DropwizardExtensionsSupport.class)
  class WhenNotConfigured {

    private final DropwizardAppExtension<HofmannConfiguration> app =
        new DropwizardAppExtension<>(HofmannApplication.class,
            ResourceHelpers.resourceFilePath("test-config.yml"));

    @Test
    void nothingIsMountedAtApiDocs() throws Exception {
      HttpResponse<String> response = get("http://localhost:" + app.getLocalPort() + "/api-docs");

      // 404 from the application, not from the docs servlet: the path is unclaimed and a
      // consumer is free to map their own resource there.
      assertThat(response.statusCode()).isEqualTo(404);
    }

    @Test
    void theApplicationItselfStillWorks() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/opaque/config");

      assertThat(response.statusCode()).isEqualTo(200);
    }
  }

  /** Opted in, at a path the consumer chose rather than the default. */
  @Nested
  @ExtendWith(DropwizardExtensionsSupport.class)
  class WhenEnabled {

    private final DropwizardAppExtension<HofmannConfiguration> app =
        new DropwizardAppExtension<>(HofmannApplication.class,
            ResourceHelpers.resourceFilePath("test-config-apidocs.yml"));

    /**
     * Asserts the status as well as the headers. Without it this would pass on a 404 — the filter
     * runs ahead of the servlet either way — and would then be claiming the docs are protected
     * when they were merely absent.
     */
    @Test
    void responsesCarryTheSecurityHeadersTheJerseyFilterCouldNotReach() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/index.html");

      assertThat(response.statusCode())
          .as("a real page is being served, so these headers are protecting something")
          .isEqualTo(200);
      assertThat(response.body()).contains("<html");
      assertThat(response.headers().firstValue("X-Frame-Options")).contains("DENY");
      assertThat(response.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
      assertThat(response.headers().firstValue("Referrer-Policy")).contains("no-referrer");
      assertThat(response.headers().firstValue("Content-Security-Policy"))
          .contains(ApiDocsSecurityHeadersFilter.CONTENT_SECURITY_POLICY);
    }

    @Test
    void theContentSecurityPolicyDeniesFramingAndThirdPartyOrigins() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/");

      String csp = response.headers().firstValue("Content-Security-Policy").orElseThrow();
      assertThat(csp).contains("default-src 'none'")
          .contains("frame-ancestors 'none'")
          .contains("form-action 'none'")
          .contains("base-uri 'none'");
    }

    /**
     * RFC 6797 §7.2: a browser ignores HSTS over plaintext, and emitting it there is misleading
     * to anyone reading the response. The test server is HTTP, so absence here is the assertion.
     */
    @Test
    void hstsIsNotSetOnAPlaintextConnection() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/index.html");

      assertThat(response.headers().firstValue("Strict-Transport-Security")).isEmpty();
    }

    /**
     * The default path is not claimed when the consumer configured a different one — otherwise
     * "configurable" would mean "additionally mounted somewhere else", which is worse than not
     * offering the option.
     */
    @Test
    void theDefaultPathIsNotAlsoClaimed() throws Exception {
      HttpResponse<String> response = get("http://localhost:" + app.getLocalPort() + "/api-docs");

      assertThat(response.statusCode()).isEqualTo(404);
      assertThat(response.headers().firstValue("Content-Security-Policy")).isEmpty();
    }

    /**
     * The OpenAPI spec gets a YAML media type rather than {@code text/html}.
     *
     * <p>Jetty has no mapping for {@code .yaml}, so the spec was going out as a rendered web page.
     * The first fix changed {@code AssetServlet}'s fallback media type to
     * {@code application/octet-stream}, which fixed the spec and broke the landing page — see
     * {@link #theMountRootStillRenders()}. Registering the RFC 9512 mapping fixes the file that
     * is actually wrong without changing what every unknown extension becomes.
     */
    @Test
    void theOpenApiSpecIsServedAsYamlRatherThanHtml() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/opaque-api.yaml");

      assertThat(response.statusCode()).isEqualTo(200);
      assertThat(response.headers().firstValue("Content-Type").orElseThrow())
          .doesNotContain("text/html")
          .contains("application/yaml");
    }

    /**
     * The bare mount path is the URL the bundle logs on startup, and it must render.
     *
     * <p>{@code AssetServlet} derives the media type from the request URI and only appends the
     * index file when the URI ends in a slash, so the extensionless mount root falls through to
     * the servlet's default. Setting that default to {@code application/octet-stream} made
     * {@code /api-docs} download a file instead of showing a page, and the {@code nosniff} header
     * added in the same commit guaranteed the browser could not recover. Caught by a reviewer;
     * the tests at the time only exercised {@code /index.html}, {@code /} and the {@code .yaml},
     * all of which happened to work.
     */
    @Test
    void theMountRootStillRenders() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs");

      assertThat(response.statusCode()).isEqualTo(200);
      assertThat(response.headers().firstValue("Content-Type").orElseThrow())
          .contains("text/html");
      assertThat(response.body()).contains("<html");
    }

    /**
     * A 404 from the asset servlet carries the headers too.
     *
     * <p>It did not. {@code AssetServlet.doGet} handles a missing asset by calling
     * {@code response.reset()} before setting the status, and {@code reset()} discards headers
     * set earlier in the chain — so every miss went out completely bare. The mechanism is not an
     * {@code ERROR} dispatch, so widening the filter's dispatcher set does not fix it; the filter
     * re-applies the headers after the chain instead. No test would have noticed, because the
     * suite passed identically either way.
     */
    @Test
    void aMissingAssetStillCarriesTheHeaders() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/does-not-exist.html");

      assertThat(response.statusCode()).isEqualTo(404);
      assertThat(response.headers().firstValue("X-Frame-Options")).contains("DENY");
      assertThat(response.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
      assertThat(response.headers().firstValue("Content-Security-Policy")).isPresent();
    }

    /**
     * The Swagger page loads its bundle from unpkg.com, so a {@code 'self'}-only policy blocked
     * the UI entirely and left the inline glue throwing a {@code ReferenceError}. This asserts
     * the policy admits what the shipped page actually references — the earlier version shipped
     * a policy that broke the page while conceding {@code 'unsafe-inline'} anyway, which is the
     * worst of both.
     */
    @Test
    void theContentSecurityPolicyAdmitsWhatTheSwaggerPageActuallyLoads() throws Exception {
      HttpResponse<String> page =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/api-docs.html");
      assertThat(page.statusCode()).isEqualTo(200);
      assertThat(page.body())
          .as("if the page stops using the CDN, tighten the policy rather than leaving it open")
          .contains("https://unpkg.com");

      assertThat(page.headers().firstValue("Content-Security-Policy").orElseThrow())
          .contains("script-src 'self' 'unsafe-inline' https://unpkg.com");
    }

    /**
     * A multi-range request beyond the cap is refused rather than amplified.
     *
     * <p>Each {@code 0-} range returns the whole resource, so without a bound a few kilobytes of
     * request produced tens of megabytes of response.
     */
    @Test
    void anAbsurdNumberOfRangesIsRefused() throws Exception {
      String ranges = "bytes=" + "0-,".repeat(500) + "0-";
      HttpResponse<String> response = HttpClient.newHttpClient().send(
          HttpRequest.newBuilder(
                  URI.create("http://localhost:" + app.getLocalPort()
                      + "/reference/docs/opaque-api.yaml"))
              .header("Range", ranges).GET().build(),
          HttpResponse.BodyHandlers.ofString());

      assertThat(response.statusCode()).isEqualTo(416);
      assertThat(response.body().length())
          .as("a refusal must not itself be the amplification")
          .isLessThan(10_000);
    }

    /** A range count a real client might send is still served. */
    @Test
    void anOrdinaryRangeRequestStillWorks() throws Exception {
      HttpResponse<String> response = HttpClient.newHttpClient().send(
          HttpRequest.newBuilder(
                  URI.create("http://localhost:" + app.getLocalPort()
                      + "/reference/docs/opaque-api.yaml"))
              .header("Range", "bytes=0-99").GET().build(),
          HttpResponse.BodyHandlers.ofString());

      assertThat(response.statusCode()).isEqualTo(206);
      assertThat(response.body()).hasSize(100);
    }
  }

  /**
   * The assets are not published by the container on their own.
   *
   * <p>They used to live under {@code META-INF/resources}, which the Servlet specification makes
   * a container-published directory and which Spring Boot serves as a static location with no
   * configuration. That meant the Spring integration exposed them too, with no switch to turn
   * them off, and a reviewer demonstrated a Spring consumer serving all four files with no CSP.
   * The commit that fixed the Dropwizard side claimed the Spring side did not have the problem;
   * it did, and only the library's own default security chain was hiding it.
   */
  @Nested
  class AssetPackaging {

    @Test
    void theAssetsAreNotUnderTheContainerPublishedDirectory() {
      assertThat(getClass().getResource("/META-INF/resources/api-docs/index.html"))
          .as("anything here is served by Spring Boot and by servlet web fragments, unasked")
          .isNull();
      assertThat(getClass().getResource("/META-INF/hofmann/api-docs/index.html"))
          .as("still shipped, just not auto-published")
          .isNotNull();
    }
  }
}
