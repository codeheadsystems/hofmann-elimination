package com.codeheadsystems.hofmann.springboot.security;

import com.codeheadsystems.hofmann.server.auth.JwtManager;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * The type Hofmann security config.
 */
@Configuration
@EnableWebSecurity
public class HofmannSecurityConfig {

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
  public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                 JwtAuthenticationFilter jwtFilter) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .headers(headers -> headers
            .frameOptions(frame -> frame.deny())
            .contentTypeOptions(content -> {})
            .httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000))
            .cacheControl(cache -> {}))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/opaque/**", "/oprf/**").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  /**
   * CORS configuration that blocks all cross-origin requests by default.
   * Override this bean in your application context to allow specific origins:
   * <pre>{@code
   *   @Bean
   *   public CorsConfigurationSource corsConfigurationSource() {
   *     CorsConfiguration config = new CorsConfiguration();
   *     config.setAllowedOrigins(List.of("https://app.example.com"));
   *     config.setAllowedMethods(List.of("GET", "POST", "DELETE"));
   *     config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
   *     UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
   *     source.registerCorsConfiguration("/**", config);
   *     return source;
   *   }
   * }**</pre>
   *
   * @return the cors configuration source
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
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
