package com.codeheadsystems.hofmann.dropwizard;

import com.codeheadsystems.hofmann.dropwizard.auth.HofmannAuthenticator;
import com.codeheadsystems.hofmann.dropwizard.auth.HofmannPrincipal;
import com.codeheadsystems.hofmann.dropwizard.health.OpaqueServerHealthCheck;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.manager.JwtKeyDetail;
import com.codeheadsystems.hofmann.server.manager.JwtManager;
import com.codeheadsystems.hofmann.server.manager.OpaqueServerKeyDetail;
import com.codeheadsystems.hofmann.server.ratelimit.FixedCapacityRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfig;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.resource.OpaqueResource;
import com.codeheadsystems.hofmann.server.resource.OprfResource;
import com.codeheadsystems.hofmann.server.oprf.VerifiableKeyConfig;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.PendingSessionStore;
import com.codeheadsystems.hofmann.server.store.RecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.hofmann.model.oprf.VerifiableOprfLimits;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.oauth.OAuthCredentialAuthFilter;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.servlets.assets.AssetServlet;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.DispatcherType;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard bundle that wires the Hofmann OPAQUE server into an existing Dropwizard application.
 * <p>
 * Registers the OPAQUE JAX-RS resource, health check, and JWT authentication filter.
 * Requires a {@link HofmannConfiguration} block in the application's YAML config.
 * <p>
 * Embed in your application with in-memory stores (dev/test only):
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>());
 * }</pre>
 * <p>
 * Or supply persistent stores (requires {@code oprfMasterKeyHex} in config):
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(myCredentialStore, mySessionStore, null));
 * }</pre>
 * <p>
 * To implement key rotation or custom key management for the OPRF endpoint:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore,
 *       () -> keyRotationService.currentDetail()));
 * }</pre>
 * <p>
 * To supply a custom {@link SecureRandom} (e.g., HSM-backed), use the fluent setter:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>().withSecureRandom(mySecureRandom));
 * }</pre>
 *
 * @param <C> the type parameter
 */
@Singleton
public class HofmannBundle<C extends HofmannConfiguration> implements ConfiguredBundle<C> {

  private static final Logger log = LoggerFactory.getLogger(HofmannBundle.class);

  private final CredentialStore credentialStore;
  private final SessionStore sessionStore;
  private final PendingSessionStore pendingSessionStore;
  private final Supplier<ServerProcessorDetail> processorDetailSupplier;
  private final RateLimitConfigSupplier rateLimitConfigSupplier;
  private final Function<RateLimitConfig, RateLimiter> rateLimiterFunction;
  private final boolean ephemeralKey;
  private SecureRandom secureRandom = new SecureRandom();
  private Supplier<JwtKeyDetail> jwtKeyDetailSupplier;
  private Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier;
  private RecoveryChallenger recoveryChallenger;
  private RecoveryTokenStore recoveryTokenStore;

  /**
   * Creates a bundle backed by in-memory stores and an ephemeral random OPRF master key.
   * <p>
   * For dev/test only — all credentials, sessions, and OPRF outputs will be lost on restart.
   * In production supply persistent stores and either a configured {@code oprfMasterKeyHex}
   * or a custom {@code Supplier<ServerProcessorDetail>}.
   */
  public HofmannBundle() {
    this.credentialStore = new InMemoryCredentialStore();
    this.sessionStore = new InMemorySessionStore();
    this.pendingSessionStore = new InMemoryPendingSessionStore();
    this.processorDetailSupplier = null;
    this.ephemeralKey = true;
    this.rateLimitConfigSupplier = new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier();
    // FixedCapacityRateLimiter, not InMemoryRateLimiter: every key these limiters see is
    // attacker-chosen — a credential identifier from an unauthenticated body, a recovery token, a
    // client address — and a map keyed on attacker-chosen values cannot be made safe by bounding
    // it. Filling it denies every caller whose bucket is not resident. The fixed-capacity
    // implementation pre-allocates, so there is no capacity condition to reach.
    this.rateLimiterFunction = FixedCapacityRateLimiter::new;
    log.warn("""
        #################################################################
        # WARNING: Using ephemeral in-memory stores and a random OPRF  #
        # master key. All data will be lost on restart.                 #
        # Do not use in production.                                     #
        #################################################################
        """);
  }


  /**
   * Creates a bundle backed by the supplied stores and an optional custom OPRF key supplier.
   * Uses a default in-memory pending session store.
   * <p>
   * When {@code processorDetailSupplier} is non-null it is called on every OPRF request,
   * allowing key rotation — and {@code oprfMasterKeyHex} in the configuration is ignored.
   * When {@code null}, {@code oprfMasterKeyHex} must be set in the configuration.
   *
   * @param credentialStore         the credential store
   * @param sessionStore            the session store
   * @param processorDetailSupplier the processor detail supplier
   */
  @Inject
  public HofmannBundle(CredentialStore credentialStore,
                       SessionStore sessionStore,
                       Supplier<ServerProcessorDetail> processorDetailSupplier) {
    this(credentialStore, sessionStore, new InMemoryPendingSessionStore(), processorDetailSupplier,
        new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier(), InMemoryRateLimiter::new);
  }

  /**
   * Creates a bundle backed by the supplied stores and an optional custom OPRF key supplier.
   * <p>
   * When {@code processorDetailSupplier} is non-null it is called on every OPRF request,
   * allowing key rotation — and {@code oprfMasterKeyHex} in the configuration is ignored.
   * When {@code null}, {@code oprfMasterKeyHex} must be set in the configuration.
   *
   * @param credentialStore         the credential store
   * @param sessionStore            the session store
   * @param pendingSessionStore     the pending session store
   * @param processorDetailSupplier the processor detail supplier
   * @param rateLimitConfigSupplier the rate limit config supplier
   * @param rateLimiterFunction the function to create rate limiters from configs
   */
  @Inject
  public HofmannBundle(CredentialStore credentialStore,
                       SessionStore sessionStore,
                       PendingSessionStore pendingSessionStore,
                       Supplier<ServerProcessorDetail> processorDetailSupplier,
                       RateLimitConfigSupplier rateLimitConfigSupplier,
                       Function<RateLimitConfig, RateLimiter> rateLimiterFunction) {
    this.credentialStore = credentialStore;
    this.sessionStore = sessionStore;
    this.pendingSessionStore = pendingSessionStore;
    this.processorDetailSupplier = processorDetailSupplier;
    this.rateLimitConfigSupplier = rateLimitConfigSupplier;
    this.rateLimiterFunction = rateLimiterFunction;
    this.ephemeralKey = false;
  }

  /**
   * Sets a custom {@link SecureRandom} to use for all random scalar generation
   * (OPRF blinding, ephemeral AKE keys, JWT secret generation when not configured).
   * If not called, a default {@link SecureRandom} is used.
   * <p>
   * Call this before the application starts (i.e., during {@code bootstrap.addBundle(...)}):
   * <pre>{@code
   *   bootstrap.addBundle(new HofmannBundle<>().withSecureRandom(mySecureRandom));
   * }</pre>
   *
   * @param secureRandom the secure random
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withSecureRandom(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
    return this;
  }

  /**
   * Sets a custom {@link Supplier Supplier&lt;JwtKeyDetail&gt;} for dynamic JWT key rotation.
   * When set, the supplier is called on every sign/verify operation, allowing key rotation
   * without server restart — and {@code jwtSecretHex} / {@code jwtPreviousSecretHex} in the
   * configuration are ignored.
   * <p>
   * Call this before the application starts (i.e., during {@code bootstrap.addBundle(...)}):
   * <pre>{@code
   *   bootstrap.addBundle(new HofmannBundle<>()
   *       .withJwtKeyDetailSupplier(() -> keyRotationService.currentJwtKeyDetail()));
   * }</pre>
   *
   * <p><strong>The supplier must be callable at construction time.</strong> {@code JwtManager}
   * calls {@code get()} in its constructor to enforce the minimum key length, so a supplier
   * backed by an external key service (Vault, KMS) must be able to answer during
   * {@code run(...)}, not only at first token issue. The same check runs on every
   * {@code issueToken}, so a rotation that introduces a key below
   * {@code JwtManager.MIN_SIGNING_KEY_BYTES} is refused rather than silently used for signing.
   *
   * @param jwtKeyDetailSupplier the jwt key detail supplier
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withJwtKeyDetailSupplier(Supplier<JwtKeyDetail> jwtKeyDetailSupplier) {
    this.jwtKeyDetailSupplier = jwtKeyDetailSupplier;
    return this;
  }

  /**
   * Sets a custom {@link Supplier Supplier&lt;OpaqueServerKeyDetail&gt;} for OPAQUE server
   * key rotation. When set, credentials registered under older key versions are authenticated
   * using the corresponding old keys, and the {@code keyRotationRequired} flag in the auth
   * response triggers client-side re-registration.
   * <p>
   * When set, {@code serverKeySeedHex}, {@code oprfSeedHex}, {@code previousServerKeySeedHex},
   * and {@code previousOprfSeedHex} in the configuration are ignored.
   *
   * @param opaqueServerKeyDetailSupplier the opaque server key detail supplier
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withOpaqueServerKeyDetailSupplier(
      Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier) {
    this.opaqueServerKeyDetailSupplier = opaqueServerKeyDetailSupplier;
    return this;
  }

  /**
   * Enables account recovery with the given {@link RecoveryChallenger} and a default
   * in-memory {@link RecoveryTokenStore}.
   *
   * @param recoveryChallenger the recovery challenger implementation
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withRecovery(RecoveryChallenger recoveryChallenger) {
    return withRecovery(recoveryChallenger, new InMemoryRecoveryTokenStore());
  }

  /**
   * Enables account recovery with the given {@link RecoveryChallenger} and a custom
   * {@link RecoveryTokenStore}.
   *
   * @param recoveryChallenger the recovery challenger implementation
   * @param recoveryTokenStore the recovery token store implementation
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withRecovery(RecoveryChallenger recoveryChallenger,
                                       RecoveryTokenStore recoveryTokenStore) {
    this.recoveryChallenger = recoveryChallenger;
    this.recoveryTokenStore = recoveryTokenStore;
    return this;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // No additional bootstrapping needed
  }

  @Override
  public void run(C configuration, Environment environment) {
    registerApiDocs(configuration, environment);

    environment.jersey().register(new SecurityHeadersFilter());
    environment.jersey().register(new CorsFilter(new HashSet<>(configuration.getCorsAllowedOrigins())));
    registerSizeLimitFilter(configuration, environment);
    OpaqueConfig opaqueConfig = buildOpaqueConfig(configuration);
    Server server = buildServer(configuration, opaqueConfig);
    JwtManager jwtManager = buildJwtManager(configuration);
    Supplier<OpaqueServerKeyDetail> keySupplier = buildOpaqueServerKeyDetailSupplier(
        configuration, server, opaqueConfig);

    OpaqueClientConfigResponse opaqueClientConfig = new OpaqueClientConfigResponse(
        configuration.getOpaqueCipherSuite(),
        configuration.getContext(),
        configuration.getArgon2MemoryKib(),
        configuration.getArgon2Iterations(),
        configuration.getArgon2Parallelism());

    RateLimiter authRateLimiter = rateLimiterFunction.apply(rateLimitConfigSupplier.authRateLimitConfig());
    RateLimiter registrationRateLimiter = rateLimiterFunction.apply(rateLimitConfigSupplier.registrationRateLimitConfig());
    RateLimiter recoveryRateLimiter = recoveryChallenger != null
        ? rateLimiterFunction.apply(rateLimitConfigSupplier.recoveryRateLimitConfig()) : null;
    HofmannOpaqueServerManager hofmannOpaqueServerManager = new HofmannOpaqueServerManager(
        keySupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter, pendingSessionStore,
        recoveryChallenger, recoveryTokenStore, recoveryRateLimiter);
    // Origin-keyed limiter in front of the unauthenticated OPAQUE endpoints. The manager's
    // limiters key on the credential identifier, which an attacker varies freely; this is the
    // only dimension that bounds a flood of distinct identifiers, and therefore the only thing
    // standing between that flood and exhaustion of the bucket map and pending-session store.
    RateLimitConfig originConfig = rateLimitConfigSupplier.originRateLimitConfig();
    // Uses rateLimiterFunction like every other limiter, so a consumer supplying a distributed
    // (e.g. Redis-backed) implementation gets cluster-wide limiting here too. Hardcoding the
    // in-process one would have silently given an N-node cluster N times the configured rate.
    RateLimiter opaqueOriginRateLimiter =
        originConfig == null ? null : rateLimiterFunction.apply(originConfig);
    environment.jersey().register(new OpaqueResource(hofmannOpaqueServerManager, opaqueClientConfig,
        opaqueOriginRateLimiter, configuration.isTrustForwardedHeaders()));
    environment.healthChecks().register("opaque-server", new OpaqueServerHealthCheck(server));

    // JWT auth filter
    HofmannAuthenticator authenticator = new HofmannAuthenticator(jwtManager);
    environment.jersey().register(new AuthDynamicFeature(
        new OAuthCredentialAuthFilter.Builder<HofmannPrincipal>()
            .setAuthenticator(authenticator)
            .setPrefix("Bearer")
            .buildAuthFilter()));
    environment.jersey().register(new AuthValueFactoryProvider.Binder<>(HofmannPrincipal.class));

    // OPRF endpoint
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(configuration.getOprfCipherSuite())
        .withRandom(secureRandom).build();
    Supplier<ServerProcessorDetail> oprfSupplier;
    if (processorDetailSupplier != null) {
      oprfSupplier = processorDetailSupplier;
    } else if (ephemeralKey) {
      oprfSupplier = buildEphemeralProcessorSupplier(configuration.getOprfProcessorId());
    } else {
      oprfSupplier = buildDefaultProcessorSupplier(configuration);
    }
    // Built before the config response rather than inline in the resource registration, because
    // the response advertises whichever of them exists. The resource still receives the same two
    // managers, so there is exactly one place deciding whether a mode is on.
    VoprfServerManager voprfServerManager = buildVoprfManager(configuration);
    PoprfServerManager poprfServerManager = buildPoprfManager(configuration);
    OprfClientConfigResponse oprfClientConfig = VerifiableKeyConfig.clientConfigResponse(
        configuration.getOprfCipherSuite(), voprfServerManager, poprfServerManager);
    OprfServerManager oprfServerManager = new OprfServerManager(oprfSuite, oprfSupplier);
    RateLimiter oprfRateLimiter = rateLimiterFunction.apply(rateLimitConfigSupplier.oprfRateLimitConfig());
    environment.jersey().register(new OprfResource(oprfServerManager, oprfClientConfig, oprfRateLimiter,
        configuration.isTrustForwardedHeaders(),
        voprfServerManager, poprfServerManager));

    // Shutdown lifecycle for manager and rate limiters
    environment.lifecycle().manage(new io.dropwizard.lifecycle.Managed() {
      @Override
      public void start() {
      }

      @Override
      public void stop() {
        hofmannOpaqueServerManager.shutdown();
        oprfRateLimiter.shutdown();
      }
    });
  }

  /**
   * Normalises a JAX-RS request path for per-path limit lookup: never null, no leading slash.
   *
   * <p>{@code UriInfo.getPath()} is specified as relative to the base URI and so should carry no
   * leading slash, but the lookup does not need to depend on that being true in every container.
   *
   * @param path the raw request path
   * @return the path without a leading slash, or the empty string if it was null
   */
  static String normalizePath(final String path) {
    if (path == null) {
      return "";
    }
    int start = path.startsWith("/") ? 1 : 0;
    int end = path.length();
    // Strip trailing slashes as well as a leading one. Jersey's path pattern for a resource
    // method is `/verifiable(/)?`, so `POST /oprf/verifiable/` routes to the same method but
    // getPath() reports "oprf/verifiable/". Matching the raw string missed, the request fell back
    // to the generic 64 KiB limit instead of the cap-derived one, and the ~470-elements-against-a
    // -cap-of-64 amplification this bound exists to close came back — for one extra character, on
    // an unauthenticated endpoint. Loop rather than a single strip: `//` routes too.
    while (end > start && path.charAt(end - 1) == '/') {
      end--;
    }
    return path.substring(start, end);
  }

  /**
   * Builds the VOPRF manager, or null when no key is configured.
   *
   * <p>Null rather than an ephemerally-keyed manager. The value of a verifiable mode is that
   * clients pin the server's public key and grade proofs against it, so a key regenerated at every
   * restart makes every previously pinned key wrong — silently, and only for clients that were
   * actually checking. A deployment that has not chosen a key is better served by the endpoint
   * answering 404.
   */
  private VoprfServerManager buildVoprfManager(C configuration) {
    String keyHex = configuration.getVoprfMasterKeyHex();
    if (!VerifiableKeyConfig.isConfigured(keyHex)) {
      return null;
    }
    OprfCipherSuite suite = VerifiableKeyConfig.suiteFor(
        configuration.getOprfCipherSuite(), OprfMode.VOPRF, secureRandom);
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        suite, keyHex, configuration.getOprfProcessorId() + "-voprf", "voprfMasterKeyHex");
    log.info("VOPRF (mode 0x01) enabled");
    return new VoprfServerManager(suite, () -> detail);
  }

  /**
   * Builds the POPRF manager, or null when no key is configured. See {@link #buildVoprfManager}.
   */
  private PoprfServerManager buildPoprfManager(C configuration) {
    String keyHex = configuration.getPoprfMasterKeyHex();
    if (!VerifiableKeyConfig.isConfigured(keyHex)) {
      return null;
    }
    OprfCipherSuite suite = VerifiableKeyConfig.suiteFor(
        configuration.getOprfCipherSuite(), OprfMode.POPRF, secureRandom);
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        suite, keyHex, configuration.getOprfProcessorId() + "-poprf", "poprfMasterKeyHex");
    log.info("POPRF (mode 0x02) enabled");
    return new PoprfServerManager(suite, () -> detail);
  }

  /**
   * Classpath location of the API doc assets.
   *
   * <p>Deliberately not under {@code META-INF/resources}, which the Servlet specification makes a
   * container-published directory — Spring Boot serves it as a static location with no
   * configuration, so the docs were reachable from consumers of the Spring integration too, with
   * no switch on that side to turn them off. Nothing auto-publishes this path.
   */
  private static final String API_DOCS_RESOURCE_PATH = "/META-INF/hofmann/api-docs";

  /**
   * Media type for assets whose extension the servlet container has no mapping for.
   *
   * <p>Left at {@code text/html}, which is {@link AssetServlet}'s own default, after a first
   * attempt at {@code application/octet-stream} broke the mount root. {@code AssetServlet} looks
   * the media type up from the request URI, and the bare mount path — {@code /api-docs}, the
   * exact URL this bundle logs on startup — has no extension, so it falls through to this default.
   * With {@code octet-stream} plus the {@code nosniff} header the landing page downloaded instead
   * of rendering, and {@code nosniff} guaranteed the browser could not recover.
   *
   * <p>The problem that change was trying to solve is real and is fixed properly instead: Jetty
   * has no {@code .yaml} mapping, so the OpenAPI spec was going out as {@code text/html} and
   * browsers rendered it as markup. {@link #registerApiDocs} now registers the RFC 9512 mapping,
   * which fixes the specs by name rather than by changing what every unknown extension becomes.
   */
  private static final String DEFAULT_ASSET_MEDIA_TYPE = "text/html";

  /**
   * Path prefixes a consumer may not mount the docs on.
   *
   * <p>A servlet mapping of {@code /opaque/*} beats Jersey's {@code /*}, so
   * {@code apiDocsPath: "/opaque"} booted cleanly and served documentation where authentication
   * used to be — every OPAQUE endpoint 404, OPRF still working, which is about as confusing as a
   * failure can get. The validator only rejected the root case while its javadoc claimed to
   * prevent exactly this.
   */
  private static final Set<String> RESERVED_API_DOCS_PREFIXES = Set.of("/opaque", "/oprf");

  /**
   * Shape a configured docs path must match: one or more slash-separated segments of unreserved
   * URI characters.
   *
   * <p>Everything outside this was accepted before, and all of it failed silently rather than
   * loudly: {@code "/*"} produced a mapping Jetty rejected only by luck, {@code "/api-docs?x=1"}
   * booted and left the docs reachable at a percent-encoded path nobody would guess, and a value
   * containing a newline was accepted as-is.
   */
  private static final Pattern API_DOCS_PATH_PATTERN =
      Pattern.compile("(/[A-Za-z0-9._~-]+)+");

  /**
   * Registers the OpenAPI specs and Swagger UI, if the consumer asked for them.
   *
   * <p>This used to run unconditionally. A bundle installs into somebody else's application, so
   * that meant claiming {@code /api-docs} and {@code /api-docs/*} on every consumer's server
   * whether or not they wanted docs served — and a consumer with their own mapping there had a
   * collision they did not create. Both the switch and the path are now theirs.
   *
   * <p>The other half of the problem is that an {@code AssetServlet} is not a JAX-RS resource, so
   * none of the filters registered through {@code environment.jersey()} below apply to it — not
   * {@link SecurityHeadersFilter}, not {@link CorsFilter}, not the body-size limit. The headers
   * are restored by registering {@link ApiDocsSecurityHeadersFilter} in the servlet chain.
   *
   * <p>The body-size limit is genuinely not applicable — {@code AssetServlet} implements only
   * {@code doGet}, so no request body is ever read. But "therefore this endpoint needs no
   * request-side defence" was the wrong conclusion from that, and a reviewer showed why: the
   * amplification vector here is a request <em>header</em>. {@code AssetServlet} places no bound
   * on the number of byte ranges in a {@code Range} header and {@code 0-} yields the whole
   * resource each time, so a 4.9 KB request returned 71.5 MB — roughly 14,600&times;,
   * unauthenticated. {@link ApiDocsSecurityHeadersFilter} caps the range count.
   *
   * @param configuration the configuration
   * @param environment   the environment
   */
  private void registerApiDocs(C configuration, Environment environment) {
    if (!configuration.isServeApiDocs()) {
      return;
    }
    String base = normalizeApiDocsPath(configuration.getApiDocsPath());
    String wildcard = base + "/*";
    // RFC 9512 registers application/yaml. Jetty has no mapping for the extension, so without
    // this the OpenAPI specs go out as text/html and a browser renders them as markup. Registered
    // on the context rather than by changing the servlet's fallback media type, so it fixes the
    // specs without changing what an unknown extension becomes — the fallback also governs the
    // extensionless mount root, and changing it there broke the landing page.
    environment.getApplicationContext().getMimeTypes().addMimeMapping("yaml", "application/yaml");
    environment.servlets()
        .addServlet("api-docs", new AssetServlet(
            API_DOCS_RESOURCE_PATH, base, "index.html",
            DEFAULT_ASSET_MEDIA_TYPE, StandardCharsets.UTF_8))
        .addMapping(base, wildcard);
    environment.servlets()
        .addFilter("api-docs-security-headers", new ApiDocsSecurityHeadersFilter(
            configuration.isTrustForwardedHeaders()))
        .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, base, wildcard);
    log.info("Serving API docs at {} (security headers applied via servlet filter)", base);
  }

  /**
   * Normalises and validates a configured docs path.
   *
   * <p>A servlet mapping is matched literally, so {@code "api-docs"} or {@code "/api-docs/"}
   * would not fail loudly — the docs would just not be reachable at the path the operator wrote
   * in their config, which is the kind of thing nobody notices until they need the docs.
   *
   * <p><strong>The validation matters more than the normalisation.</strong> An earlier version
   * rejected only a path that normalised to empty, on the reasoning that serving at the root
   * would shadow the API. It would — but so does any prefix that collides with a real one, and
   * {@code /opaque/*} beats Jersey's {@code /*}: {@code apiDocsPath: "/opaque"} started cleanly
   * and served documentation in place of every authentication endpoint, while OPRF kept working.
   * Silent, and confusing enough that the cause would not be obvious.
   *
   * @param path the configured path
   * @return the normalised path
   * @throws IllegalArgumentException if the path is empty, malformed, or would shadow the API
   */
  static String normalizeApiDocsPath(String path) {
    String trimmed = path == null ? "" : path.trim();
    while (trimmed.endsWith("/")) {
      trimmed = trimmed.substring(0, trimmed.length() - 1);
    }
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException(
          "apiDocsPath must name a path prefix; serving docs at the root would shadow the API");
    }
    String normalized = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
    if (!API_DOCS_PATH_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException(
          "apiDocsPath must be one or more '/'-separated segments of unreserved URI characters, "
              + "but was: " + normalized);
    }
    // '.' is an unreserved character, so the pattern alone admits dot segments. A servlet mapping
    // is matched literally rather than resolved, so "/api-docs/../.." becomes a mapping nothing
    // can ever request — the docs would simply be unreachable, with no error to explain why.
    for (String segment : normalized.substring(1).split("/")) {
      if (".".equals(segment) || "..".equals(segment)) {
        throw new IllegalArgumentException(
            "apiDocsPath may not contain '.' or '..' segments; servlet mappings are matched "
                + "literally rather than resolved, so the docs would be unreachable: " + normalized);
      }
    }
    String firstSegment = normalized.indexOf('/', 1) < 0
        ? normalized : normalized.substring(0, normalized.indexOf('/', 1));
    if (RESERVED_API_DOCS_PREFIXES.contains(firstSegment.toLowerCase(Locale.ROOT))) {
      throw new IllegalArgumentException(
          "apiDocsPath may not start with " + firstSegment + ": a servlet mapping there takes "
              + "precedence over the Jersey resources and would replace the API with documentation");
    }
    return normalized;
  }

  private void registerSizeLimitFilter(C configuration, Environment environment) {
    long defaultMaxBytes = configuration.getMaxRequestBodyBytes();
    // The batched verifiable endpoints get a tighter, cap-derived limit. The generic limit bounds
    // memory but not element count: at 64 KiB it admits roughly 470 hex-encoded P-521 elements
    // against a configured batch cap of 64, and every one is parsed before the manager rejects the
    // batch. min() rather than the override outright, so lowering the generic limit still wins.
    long verifiableMaxBytes = Math.min(defaultMaxBytes,
        VerifiableOprfLimits.maxRequestBodyBytes(VoprfServerManager.DEFAULT_MAX_BATCH_SIZE));
    // Keyed without a leading slash and matched after stripping one, so it does not matter
    // whether the container reports "oprf/verifiable" or "/oprf/verifiable". Getting that wrong
    // would not fail — the bound would just silently stop applying, which is the failure mode
    // worth designing out rather than asserting against.
    Map<String, Long> perPath = Map.of(
        "oprf/verifiable", verifiableMaxBytes,
        "oprf/partially-oblivious", verifiableMaxBytes);
    ContainerRequestFilter filter = (ContainerRequestContext ctx) -> {
      long maxBytes = perPath.getOrDefault(
          normalizePath(ctx.getUriInfo().getPath()), defaultMaxBytes);
      long length = ctx.getLength();
      if (length > maxBytes) {
        ctx.abortWith(Response.status(Response.Status.REQUEST_ENTITY_TOO_LARGE)
            .entity("Request body exceeds maximum allowed size")
            .build());
        return;
      }
      // Content-Length is -1 for chunked transfer encoding, so the check above does not catch a
      // streamed oversized body. Bound the entity stream as well so the limit is enforced as the
      // body is read regardless of how it is framed.
      ctx.setEntityStream(new BoundedInputStream(ctx.getEntityStream(), maxBytes));
    };
    environment.jersey().register(filter);
  }

  /**
   * Wraps an entity stream and aborts with HTTP 413 once more than {@code maxBytes} have been
   * read, defending against oversized chunked request bodies that carry no Content-Length.
   */
  private static final class BoundedInputStream extends FilterInputStream {
    private final long maxBytes;
    private long count;

    BoundedInputStream(InputStream in, long maxBytes) {
      super(in);
      this.maxBytes = maxBytes;
    }

    @Override
    public int read() throws IOException {
      int b = super.read();
      if (b != -1) {
        increment(1);
      }
      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int n = super.read(b, off, len);
      if (n > 0) {
        increment(n);
      }
      return n;
    }

    private void increment(int read) {
      count += read;
      if (count > maxBytes) {
        throw new WebApplicationException(
            Response.status(Response.Status.REQUEST_ENTITY_TOO_LARGE)
                .entity("Request body exceeds maximum allowed size")
                .build());
      }
    }
  }

  private JwtManager buildJwtManager(C configuration) {
    Supplier<JwtKeyDetail> supplier;
    if (jwtKeyDetailSupplier != null) {
      supplier = jwtKeyDetailSupplier;
    } else {
      String secretHex = configuration.getJwtSecretHex();
      byte[] secret;
      if (secretHex == null || secretHex.isEmpty()) {
        requireEphemeralKeysAllowed(configuration, "jwtSecretHex",
            "tokens minted by one node will be rejected by every other, and a restart "
                + "invalidates every session");
        log.warn("No JWT secret configured — generating an ephemeral one because "
            + "allowEphemeralKeys is set. Tokens will be invalidated on restart. "
            + "Do not use in production.");
        secret = new byte[32];
        secureRandom.nextBytes(secret);
      } else {
        secret = HexFormat.of().parseHex(secretHex);
      }

      String previousHex = configuration.getJwtPreviousSecretHex();
      byte[] previousSecret = null;
      if (previousHex != null && !previousHex.isEmpty()) {
        previousSecret = HexFormat.of().parseHex(previousHex);
      }

      JwtKeyDetail detail = new JwtKeyDetail(secret, previousSecret);
      supplier = () -> detail;
    }
    return new JwtManager(supplier, configuration.getJwtIssuer(),
        configuration.getJwtTtlSeconds(), sessionStore);
  }

  private Supplier<OpaqueServerKeyDetail> buildOpaqueServerKeyDetailSupplier(
      C configuration, Server currentServer, OpaqueConfig opaqueConfig) {
    if (opaqueServerKeyDetailSupplier != null) {
      return opaqueServerKeyDetailSupplier;
    }

    String prevKeySeedHex = configuration.getPreviousServerKeySeedHex();
    String prevOprfSeedHex = configuration.getPreviousOprfSeedHex();

    boolean hasPrevKeySeed = prevKeySeedHex != null && !prevKeySeedHex.isEmpty();
    boolean hasPrevOprfSeed = prevOprfSeedHex != null && !prevOprfSeedHex.isEmpty();

    if (hasPrevKeySeed != hasPrevOprfSeed) {
      throw new IllegalStateException(
          "Both previousServerKeySeedHex and previousOprfSeedHex must be configured together "
              + "(or both omitted when no key rotation is in progress).");
    }

    if (!hasPrevKeySeed) {
      OpaqueServerKeyDetail detail = new OpaqueServerKeyDetail(currentServer);
      return () -> detail;
    }

    Server previousServer = buildServerFromSeeds(prevKeySeedHex, prevOprfSeedHex, opaqueConfig);
    OpaqueServerKeyDetail detail = new OpaqueServerKeyDetail(
        1, currentServer, java.util.Map.of(0, previousServer));
    return () -> detail;
  }

  private Server buildServerFromSeeds(String keySeedHex, String oprfSeedHex, OpaqueConfig opaqueConfig) {
    HexFormat hex = HexFormat.of();
    OpaqueCipherSuite suite = opaqueConfig.cipherSuite();
    byte[] keySeed = hex.parseHex(keySeedHex);
    byte[] oprfSeed = hex.parseHex(oprfSeedHex);
    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(keySeed);
    BigInteger sk = keyPair.privateKey();
    byte[] pk = keyPair.publicKeyBytes();
    // Canonical per-suite scalar encoding, matching what Server's constructor decodes:
    // big-endian on the NIST curves, little-endian on ristretto255. See Server's javadoc.
    byte[] skFixed = opaqueConfig.cipherSuite().oprfSuite().groupSpec().serializeScalar(sk);
    return new Server(skFixed, pk, oprfSeed, opaqueConfig);
  }

  private OpaqueConfig buildOpaqueConfig(C configuration) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(configuration.getOpaqueCipherSuite())
        .withRandom(secureRandom).build();
    OpaqueCipherSuite suite = new OpaqueCipherSuite(oprfSuite);
    byte[] context = configuration.getContext().getBytes(StandardCharsets.UTF_8);
    if (configuration.getArgon2MemoryKib() == 0) {
      if (!configuration.isAllowIdentityKsf()) {
        throw new IllegalStateException(
            "Argon2 is disabled (argon2MemoryKib=0) but allowIdentityKsf is false. "
                + "Set allowIdentityKsf: true to explicitly allow the identity KSF "
                + "(no key stretching). Do not use identity KSF in production.");
      }
      log.warn("Argon2 disabled — using identity KSF. Do not use in production.");
      return new OpaqueConfig(suite, 0, 0, 0, context, new OpaqueConfig.IdentityKsf(), new RandomProvider(secureRandom));
    }
    // withRandomConfig is not decoration. OpaqueConfig.withArgon2id builds its own
    // `new RandomProvider()` internally, so without this the deployment's SecureRandom reached the
    // identity-KSF branch above and was silently dropped on this one — the production branch. An
    // operator wiring an HSM-backed source got it for OPRF scalars and blinds, and the platform
    // default for every OPAQUE masking nonce, server AKE key seed, server nonce, envelope nonce
    // and client nonce. No symptom; exactly inverted from the intent.
    return OpaqueConfig.withArgon2id(
        suite,
        context,
        configuration.getArgon2MemoryKib(),
        configuration.getArgon2Iterations(),
        configuration.getArgon2Parallelism())
        .withRandomConfig(new RandomProvider(secureRandom));
  }

  /**
   * Refuses to start when key material is missing, unless the deployment has explicitly opted in
   * to ephemeral keys.
   * <p>
   * Mirrors the treatment {@code oprfMasterKeyHex} and {@code allowIdentityKsf} already receive.
   * The generated key is random per process, so this is not a key-disclosure risk — the failure
   * is availability and consistency, and it surfaces as intermittent authentication failures well
   * after deployment rather than at the point of the mistake.
   */
  private void requireEphemeralKeysAllowed(C configuration, String setting, String consequence) {
    if (!configuration.isAllowEphemeralKeys()) {
      throw new IllegalStateException(
          setting + " is not configured. Generating key material at startup means " + consequence
              + ". Configure it (openssl rand -hex 32), or set allowEphemeralKeys: true to accept "
              + "ephemeral keys — appropriate for local development, not for production.");
    }
  }

  private Server buildServer(C configuration, OpaqueConfig opaqueConfig) {
    String keySeedHex = configuration.getServerKeySeedHex();
    String oprfSeedHex = configuration.getOprfSeedHex();

    boolean hasKeySeed = keySeedHex != null && !keySeedHex.isEmpty();
    boolean hasOprfSeed = oprfSeedHex != null && !oprfSeedHex.isEmpty();

    if (!hasKeySeed && !hasOprfSeed) {
      requireEphemeralKeysAllowed(configuration, "serverKeySeedHex and oprfSeedHex",
          "credentials registered against one node cannot authenticate against another, and a "
              + "restart invalidates every registration");
      log.warn("No server key seed or OPRF seed configured — generating ephemeral ones because "
          + "allowEphemeralKeys is set. All registrations will be invalidated on restart. "
          + "Do not use in production.");
      return Server.generate(opaqueConfig);
    }

    if (!hasKeySeed || !hasOprfSeed) {
      throw new IllegalStateException(
          "Both serverKeySeedHex and oprfSeedHex must be configured together "
              + "(or both omitted for dev mode).");
    }

    HexFormat hex = HexFormat.of();
    OpaqueCipherSuite suite = opaqueConfig.cipherSuite();
    byte[] keySeed = hex.parseHex(keySeedHex);
    byte[] oprfSeed = hex.parseHex(oprfSeedHex);

    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(keySeed);
    BigInteger sk = keyPair.privateKey();
    byte[] pk = keyPair.publicKeyBytes();

    // Canonical per-suite scalar encoding, matching what Server's constructor decodes:
    // big-endian on the NIST curves, little-endian on ristretto255. See Server's javadoc.
    byte[] skFixed = opaqueConfig.cipherSuite().oprfSuite().groupSpec().serializeScalar(sk);

    return new Server(skFixed, pk, oprfSeed, opaqueConfig);
  }

  private Supplier<ServerProcessorDetail> buildEphemeralProcessorSupplier(String processorId) {
    // randomScalar() via the configured SecureRandom is intentional — ephemeral mode is dev/test only.
    BigInteger masterKey = OprfCipherSuite.builder()
        .withRandomProvider(new RandomProvider(secureRandom))
        .withSuite(CurveHashSuite.P256_SHA256)
        .build().randomScalar();
    ServerProcessorDetail detail = new ServerProcessorDetail(masterKey, processorId);
    return () -> detail;
  }

  private Supplier<ServerProcessorDetail> buildDefaultProcessorSupplier(C configuration) {
    String masterKeyHex = configuration.getOprfMasterKeyHex();
    if ((masterKeyHex == null || masterKeyHex.isEmpty()) && configuration.isAllowEphemeralKeys()) {
      // allowEphemeralKeys has to cover every piece of key material or it is not an escape hatch:
      // leaving this one out meant the documented "set allowEphemeralKeys for a throwaway run"
      // still failed on the next setting along.
      log.warn("No OPRF master key configured — generating an ephemeral one because "
          + "allowEphemeralKeys is set. OPRF outputs will not be stable across restarts. "
          + "Do not use in production.");
      OprfCipherSuite suite =
          OprfCipherSuite.builder().withSuite(configuration.getOprfCipherSuite()).build();
      ServerProcessorDetail ephemeral =
          new ServerProcessorDetail(suite.randomScalar(), configuration.getOprfProcessorId());
      return () -> ephemeral;
    }
    if (masterKeyHex == null || masterKeyHex.isEmpty()) {
      throw new IllegalStateException(
          "oprfMasterKeyHex must be configured for the OPRF endpoint. "
              + "Generate a value with: openssl rand -hex 32. "
              + "Alternatively, supply a custom Supplier<ServerProcessorDetail> to the HofmannBundle constructor.");
    }
    BigInteger masterKey = new BigInteger(masterKeyHex, 16);
    // Fail at startup rather than silently running with an unusable key: a key congruent to
    // zero modulo the group order makes every OPRF evaluation return the identity element, and
    // on ristretto255 that decodes cleanly, so the deployment would look healthy while having
    // no effective key at all. Normalizing also folds a key at or above the order into range —
    // the documented `openssl rand -hex 32` exceeds ristretto255's order about 94% of the time
    // — so two configs differing by a multiple of the order stop looking like distinct keys.
    // This changes no output: scalar multiplication reduces modulo the order regardless.
    masterKey = OprfCipherSuite.builder().withSuite(configuration.getOprfCipherSuite()).build()
        .normalizeSecretKey(masterKey);
    String processorId = configuration.getOprfProcessorId();
    ServerProcessorDetail detail = new ServerProcessorDetail(masterKey, processorId);
    return () -> detail;
  }
}
