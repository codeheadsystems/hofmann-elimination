package com.codeheadsystems.hofmann.springboot.security;

import com.codeheadsystems.hofmann.server.auth.JwtManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/opaque/**", "/oprf/**", "/actuator/health").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}
