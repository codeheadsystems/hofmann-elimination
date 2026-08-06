package com.codeheadsystems.hofmann.springboot.security;

import com.codeheadsystems.hofmann.server.manager.JwtManager;
import jakarta.servlet.DispatcherType;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
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
@Configuration
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
