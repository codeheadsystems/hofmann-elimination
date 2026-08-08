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
     * An extension the container has no mapping for must not fall back to {@code text/html}.
     *
     * <p>Found by probing rather than by reading: {@code AssetServlet}'s four-argument
     * constructor defaults unmapped extensions to {@code text/html}, so the OpenAPI spec was
     * going out as a web page — a browser rendered YAML as markup. The content is the deployer's
     * own, so this is a correctness problem before it is a security one, but combined with
     * {@code nosniff} it is now firmly the right thing rather than firmly the wrong one.
     */
    @Test
    void anUnmappedExtensionIsNotServedAsHtml() throws Exception {
      HttpResponse<String> response =
          get("http://localhost:" + app.getLocalPort() + "/reference/docs/opaque-api.yaml");

      assertThat(response.statusCode()).isEqualTo(200);
      assertThat(response.headers().firstValue("Content-Type").orElseThrow())
          .doesNotContain("text/html")
          .contains("application/octet-stream");
    }
  }
}
