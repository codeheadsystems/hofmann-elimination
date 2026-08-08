package com.codeheadsystems.hofmann.springboot.security;

import com.codeheadsystems.hofmann.server.manager.JwtManager;
import com.codeheadsystems.hofmann.springboot.config.HofmannAutoConfiguration;
import jakarta.servlet.DispatcherType;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Default Spring Security configuration for a Hofmann-based application.
 *
 * <p><strong>An {@code @AutoConfiguration} in its own right, listed in
 * {@code AutoConfiguration.imports}, rather than a plain {@code @Configuration} imported from
 * {@link HofmannAutoConfiguration}.</strong> That is what makes the back-off below work for a
 * consumer whose component scan reaches this package, and it is not a stylistic choice.
 *
 * <p>As a plain {@code @Configuration} in a scannable package, this class could be picked up
 * twice: once through the auto-configuration import, and again as an ordinary user configuration
 * if the application's {@code @ComponentScan} covered
 * {@code com.codeheadsystems.hofmann.springboot}. Scanned in, it loses the deferred phase that
 * guarantees auto-configuration is read last, so {@code @ConditionalOnMissingBean} was evaluated
 * before the application's own {@code @Bean} was registered, found nothing, registered this chain
 * anyway, and the application died with {@code UnreachableFilterChainException}. An
 * {@code @AutoConfiguration} class cannot be scanned in — Boot's
 * {@code AutoConfigurationExcludeFilter} excludes it by construction.
 *
 * <p>Not hypothetical: {@code IntegrationTestApplication} in this repository scans
 * {@code com.codeheadsystems.hofmann.springboot} explicitly, commented as picking up "controllers
 * and security config". That is in-repo documented practice, so a consumer who copied it hit this.
 *
 * <p><strong>An earlier version of this note claimed the condition was evaluated too early for
 * every consumer. That was wrong.</strong> A consumer who does not scan this package backed off
 * correctly before the change; a reviewer demonstrated it by booting one. The same reviewer showed
 * the {@code ApplicationContextRunner} test previously covering this was not "worse than absent"
 * as I had written, but incomplete — it exercised the non-scanning path and told the truth about
 * it, while saying nothing about the scanning one. Both paths now have real
 * {@code @SpringBootTest} coverage: {@code SecurityChainBackOffTest} for a consumer that scans
 * this package, {@code NonScanningConsumerBackOffTest} for one that does not.
 *
 * <p>One residual this does not fix: a consumer whose own <em>auto-configuration</em> contributes
 * the chain still collides, and which one wins is decided by alphabetical class name, because
 * {@code AutoConfigurationSorter} sorts that way before applying before/after ordering. Such a
 * consumer should declare {@code @AutoConfiguration(before = HofmannSecurityConfig.class)}.
 *
 * <p><strong>This chain is only registered when the application defines no
 * {@link SecurityFilterChain} of its own.</strong> It is unscoped by design — it applies to every
 * URL, so that the JWT filter authenticates the consumer's own endpoints, which is the point of
 * the library. That is safe only while it is the sole chain: two chains are applied in order and
 * the first match wins per request. An unconditional unscoped chain is therefore incompatible
 * with a consumer that has one: on Spring Security 6.2+ two any-request chains fail fast with
 * {@code UnreachableFilterChainException} and the application refuses to boot, and a consumer
 * whose own chain is scoped silently ends up with this one governing everything else.
 *
 * <p><strong>Taking over means taking over completely.</strong> The condition triggers on the
 * presence of any chain, not on what it matches, so a chain scoped with
 * {@code securityMatcher("/api/**")} still displaces this one — and everything outside that
 * matcher is then served with no chain at all. That is a fail-open gap in the consumer's
 * application, and it is easy to arrive at by accident, because an unscoped consumer chain used
 * to crash at startup with a message recommending {@code securityMatcher}. End your chain with
 * {@code anyRequest().authenticated()} rather than scoping it, unless you have deliberately
 * arranged coverage for the remainder.
 *
 * <p>Adopting this configuration also means every URL in the application requires a Hofmann JWT
 * unless explicitly permitted — including endpoints you intend to be public.
 *
 * <p>An application that needs its own chain wires {@link JwtAuthenticationFilter} — still
 * exposed as a bean — into it:
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain appSecurity(HttpSecurity http, JwtAuthenticationFilter jwtFilter)
 *     throws Exception {
 *   return http
 *       .authorizeHttpRequests(auth -> auth
 *           .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
 *           .requestMatchers("/opaque/**", "/oprf/**").permitAll()
 *           .anyRequest().authenticated())
 *       .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
 *       .build();
 * }
 * }</pre>
 *
 * <p>Note that {@code /opaque/**} and {@code /oprf/**} must be permitted: the OPAQUE handshake is
 * how a caller obtains a token, so requiring one to reach it would be circular. The endpoints
 * that do need authentication — credential deletion and password change — verify the bearer
 * token themselves and check that its subject matches the credential being acted on.
 */
@AutoConfiguration(
    // `after` is load-bearing rather than decorative: @ConditionalOnBean below can only see beans
    // an earlier auto-configuration has already contributed, and JwtManager comes from
    // HofmannAutoConfiguration.
    after = HofmannAutoConfiguration.class,
    // Without this, winning against Boot's own default chain is decided by alphabetical class
    // name — `com.codeheadsystems` happens to sort before `org.springframework`. Deliberate beats
    // lucky.
    before = ServletWebSecurityAutoConfiguration.class)
// Excluding HofmannAutoConfiguration via spring.autoconfigure.exclude used to disable the library
// cleanly, because this class was imported from it. Now that it stands alone, excluding the other
// half would leave this chain reaching for a JwtManager that no longer exists — a startup failure
// with NoSuchBeanDefinitionException where the consumer had asked for the library to be off.
@ConditionalOnBean(JwtManager.class)
// Matches what Boot does for its own chain. A non-servlet application has nothing for a filter
// chain to filter, and registering one there is inert at best.
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
public class HofmannSecurityConfig {

  /**
   * Order for the default chain: last, matching Spring Boot's own default.
   * <p>
   * A chain that matches every request must be published after any narrower one, or the narrower
   * one can never be reached. In practice this value is inert — the chain only exists when the
   * application has none of its own, and Spring Security 6.2+ rejects two any-request chains
   * outright — but a catch-all registered early is the wrong shape to leave in place for whoever
   * changes the condition next.
   *
   * <p><strong>If this value ever stops being inert, its test has to change with it.</strong>
   * {@code AutoConfigurationRegistrationTest.catchAllChainIsOrderedLast} asserts the value of this
   * constant, not the order of the chains actually registered — so it cannot notice the
   * {@code @Order} annotation being removed from the {@code @Bean} below, which is the failure its
   * own javadoc claims to guard against. That is acceptable only while the chain cannot coexist
   * with a consumer's. The moment it can, this constant becomes the thing standing between a
   * catch-all and a narrower chain it would shadow, and the test must assert the registered order
   * instead.
   */
  public static final int HOFMANN_CHAIN_ORDER = Ordered.LOWEST_PRECEDENCE - 5;

  /**
   * Jwt authentication filter jwt authentication filter.
   *
   * @param jwtManager the jwt manager
   * @return the jwt authentication filter
   */
  @Bean
  public JwtAuthenticationFilter jwtAuthenticationFilter(JwtManager jwtManager) {
    return new JwtAuthenticationFilter(jwtManager);
  }

  /**
   * Security filter chain security filter chain.
   *
   * @param http      the http
   * @param jwtFilter the jwt filter
   * @return the security filter chain
   * @throws Exception the exception
   */
  @Bean
  @Order(HOFMANN_CHAIN_ORDER)
  @ConditionalOnMissingBean(SecurityFilterChain.class)
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      JwtAuthenticationFilter jwtFilter,
      @Qualifier("hofmannCorsConfigurationSource") CorsConfigurationSource corsSource,
      @Value("${server.error.path:${error.path:/error}}") String errorPath) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .cors(cors -> cors.configurationSource(corsSource))
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .headers(headers -> headers
            .frameOptions(frame -> frame.deny())
            .contentTypeOptions(content -> {})
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000))
            .cacheControl(cache -> {}))
        .authorizeHttpRequests(auth -> auth
            // Permit the ERROR dispatch, but ONLY to the error path. Without this, Spring
            // forwards to /error, this chain treats it as an unauthenticated request, and the
            // entry point below rewrites it to 401 — so every 400, 429 and 503 the controllers
            // raise reaches the client as "unauthorized". A throttled client would re-prompt for
            // a password instead of backing off.
            //
            // Permitting the ERROR dispatch to ANY path would be a bypass: an application that
            // registers a custom error page pointing at a protected controller — an ordinary
            // Spring Boot feature — would serve that controller's body to unauthenticated
            // callers, reachable by sending a malformed request to any permitted endpoint.
            .requestMatchers(new AndRequestMatcher(
                new DispatcherTypeRequestMatcher(DispatcherType.ERROR),
                PathPatternRequestMatcher.withDefaults().matcher(errorPath))).permitAll()
            .requestMatchers("/opaque/**", "/oprf/**").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  /**
   * CORS configuration that blocks all cross-origin requests by default.
   *
   * <p>Deliberately NOT named {@code corsConfigurationSource}. Spring Security's {@code .cors()}
   * resolves a bean by that exact name in preference to anything else, so a library publishing
   * one would silently override an application that configures CORS the ordinary MVC way via
   * {@code WebMvcConfigurer.addCorsMappings} — even when this chain has correctly backed off in
   * favour of the application's own. It would also collide outright with an application that
   * declared its own bean of that name, failing startup with
   * {@code BeanDefinitionOverrideException}.
   *
   * <p>Override by declaring a bean of this name:
   *
   * <pre>{@code
   *   @Bean
   *   CorsConfigurationSource hofmannCorsConfigurationSource() {
   *     CorsConfiguration config = new CorsConfiguration();
   *     config.setAllowedOrigins(List.of("https://app.example.com"));
   *     config.setAllowedMethods(List.of("GET", "POST", "DELETE"));
   *     config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
   *     UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
   *     source.registerCorsConfiguration("/**", config);
   *     return source;
   *   }
   * }***</pre>
   *
   * @return the cors configuration source
   */
  @Bean
  @ConditionalOnMissingBean(name = "hofmannCorsConfigurationSource")
  public CorsConfigurationSource hofmannCorsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    // No allowed origins by default — all cross-origin requests are blocked.
    // Override this bean to permit specific origins for your deployment.
    config.setAllowedOrigins(List.of());
    config.setAllowedMethods(List.of("GET", "POST", "DELETE"));
    config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }
}
