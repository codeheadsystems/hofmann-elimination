package com.codeheadsystems.hofmann.springboot.security;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * The documented escape hatch works in a real application.
 *
 * <p><strong>These boot actual {@code @SpringBootTest} contexts, and that is the whole point.</strong>
 * The back-off was previously covered by an {@code ApplicationContextRunner} test, which registers
 * user beans directly on the context before refresh — so {@code @ConditionalOnMissingBean} sees
 * them and backs off. In a real application the user's beans are registered by the configuration
 * class post-processor instead, and a {@code @Bean} on an imported plain {@code @Configuration}
 * was evaluated first: the condition reported "did not find any beans", registered the library's
 * chain anyway, and the application died with {@code UnreachableFilterChainException}.
 *
 * <p>So the runner reported success on a configuration that could not start. A consumer copying
 * the example out of {@link HofmannSecurityConfig}'s javadoc got a crash. Fixed by making
 * {@code HofmannSecurityConfig} an {@code @AutoConfiguration} listed in
 * {@code AutoConfiguration.imports}, rather than a plain {@code @Configuration} imported from
 * another auto-configuration.
 *
 * <p>Verified causally rather than by inspection: with the fix reverted both cases below fail with
 * {@code UnreachableFilterChainException}; with it applied both pass.
 */
class SecurityChainBackOffTest {

  // Individual constants rather than a String[]: an annotation value must be a compile-time
  // constant expression, and an array field reference is not one.
  static final String OPRF_KEY = "hofmann.oprf-master-key-hex=2a";
  static final String JWT_SECRET =
      "hofmann.jwt-secret-hex=abababababababababababababababababababababababababababababababab";
  static final String SERVER_SEED =
      "hofmann.server-key-seed-hex=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
  static final String OPRF_SEED =
      "hofmann.oprf-seed-hex=efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

  /**
   * The exact shape the javadoc tells a consumer to write: a {@code @Bean} on the
   * {@code @SpringBootApplication} class, no {@code @Order}, wiring in the exposed JWT filter.
   */
  @Nested
  @SpringBootTest(classes = ChainOnTheApplicationClass.ConsumerApp.class, properties = {OPRF_KEY, JWT_SECRET, SERVER_SEED, OPRF_SEED})
  class ChainOnTheApplicationClass {

    @SpringBootApplication
    static class ConsumerApp {
      @Bean
      SecurityFilterChain appSecurity(HttpSecurity http, JwtAuthenticationFilter jwtFilter)
          throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                .requestMatchers("/opaque/**", "/oprf/**").permitAll()
                .anyRequest().authenticated())
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
      }
    }

    @Autowired private ApplicationContext context;

    @Test
    void theLibraryChainBacksOffEntirely() {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .as("two chains means the library's did not back off, and startup would have failed")
          .containsExactly("appSecurity");
    }

    /** The filter has to stay available, or the example in the javadoc cannot be written. */
    @Test
    void theJwtFilterIsStillExposedForTheApplicationToWireIn() {
      assertThat(context.getBeanNamesForType(JwtAuthenticationFilter.class)).hasSize(1);
    }
  }

  /** The other ordinary shape: a separate {@code @Configuration} class. Also failed before. */
  @Nested
  @SpringBootTest(
      classes = {ChainInASeparateConfiguration.ConsumerApp.class,
          ChainInASeparateConfiguration.SeparateSecurity.class},
      properties = {OPRF_KEY, JWT_SECRET, SERVER_SEED, OPRF_SEED})
  class ChainInASeparateConfiguration {

    @SpringBootApplication
    static class ConsumerApp {
    }

    @Configuration
    static class SeparateSecurity {
      @Bean
      SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
      }
    }

    @Autowired private ApplicationContext context;

    @Test
    void theLibraryChainBacksOffEntirely() {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .containsExactly("appSecurity");
    }
  }

  /**
   * With no chain of its own, the application gets the library's — otherwise "backs off" would be
   * indistinguishable from "never registered", and every assertion above would pass vacuously.
   */
  @Nested
  @SpringBootTest(classes = ApplicationWithNoChainOfItsOwn.ConsumerApp.class, properties = {OPRF_KEY, JWT_SECRET, SERVER_SEED, OPRF_SEED})
  class ApplicationWithNoChainOfItsOwn {

    @SpringBootApplication
    static class ConsumerApp {
    }

    @Autowired private ApplicationContext context;

    @Test
    void theLibraryChainIsRegistered() {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .containsExactly("securityFilterChain");
    }
  }
}
