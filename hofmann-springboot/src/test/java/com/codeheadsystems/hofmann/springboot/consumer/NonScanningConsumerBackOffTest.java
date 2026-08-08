package com.codeheadsystems.hofmann.springboot.consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.codeheadsystems.hofmann.springboot.security.JwtAuthenticationFilter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The consumer who does <em>not</em> component-scan the library's package.
 *
 * <p>This package is a sibling of {@code ...springboot.security}, so the applications below scan
 * neither it nor anything under it — which is the ordinary case, and the one
 * {@code SecurityChainBackOffTest} cannot cover, because that test lives in the library's own
 * package and its applications therefore scan the library in.
 *
 * <p><strong>This path already worked before the auto-configuration change.</strong> It is here
 * because a reviewer pointed out that moving all the coverage into the library's package left the
 * ordinary consumer untested — the removed {@code ApplicationContextRunner} test had been the only
 * thing exercising it. Losing coverage of the case that was never broken, while fixing the case
 * that was, is a quiet way to make a fix look bigger than it is.
 */
class NonScanningConsumerBackOffTest {

  static final String OPRF_KEY = "hofmann.oprf-master-key-hex=2a";
  static final String JWT_SECRET =
      "hofmann.jwt-secret-hex=abababababababababababababababababababababababababababababababab";
  static final String SERVER_SEED =
      "hofmann.server-key-seed-hex=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
  static final String OPRF_SEED =
      "hofmann.oprf-seed-hex=efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

  @Nested
  @SpringBootTest(classes = WithItsOwnChain.ConsumerApp.class,
      properties = {OPRF_KEY, JWT_SECRET, SERVER_SEED, OPRF_SEED})
  class WithItsOwnChain {

    @SpringBootApplication
    static class ConsumerApp {
      @Bean
      SecurityFilterChain appSecurity(HttpSecurity http, JwtAuthenticationFilter jwtFilter)
          throws Exception {
        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
      }
    }

    @Autowired private ApplicationContext context;

    @Test
    void theLibraryChainBacksOff() {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .containsExactly("appSecurity");
    }
  }

  @Nested
  @SpringBootTest(classes = WithNoChainOfItsOwn.ConsumerApp.class,
      properties = {OPRF_KEY, JWT_SECRET, SERVER_SEED, OPRF_SEED})
  class WithNoChainOfItsOwn {

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

  /**
   * Excluding the library's auto-configuration must actually disable it.
   *
   * <p>A regression introduced by making this class independent, and caught in review rather than
   * by me: while the security config was {@code @Import}ed, excluding
   * {@code HofmannAutoConfiguration} took both halves out together. Standing alone, it stayed
   * loaded and reached for a {@code JwtManager} that the exclusion had just removed — so asking
   * for the library to be off produced {@code NoSuchBeanDefinitionException} at startup instead.
   * {@code @ConditionalOnBean(JwtManager.class)} is what makes the two halves leave together
   * again.
   *
   * <p><strong>Runs as a SERVLET application deliberately.</strong> A first version used
   * {@code WebApplicationType.NONE} and was vacuous: {@code @ConditionalOnWebApplication(SERVLET)}
   * means a non-web application never loads this configuration at all, so the test passed whether
   * or not {@code @ConditionalOnBean} was present. Caught by removing the annotation and finding
   * the test still green.
   */
  @Test
  void excludingTheLibraryAutoConfigurationDisablesTheSecurityChainToo() {
    try (ConfigurableApplicationContext context = new SpringApplicationBuilder(ExcludedApp.class)
        .properties("spring.autoconfigure.exclude="
            + "com.codeheadsystems.hofmann.springboot.config.HofmannAutoConfiguration")
        .properties("server.port=0")
        .web(org.springframework.boot.WebApplicationType.SERVLET)
        .run()) {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .as("the library's chain must go when the library is excluded")
          .doesNotContain("securityFilterChain");
    }
  }

  @Test
  void excludingTheLibraryDoesNotBreakStartup() {
    assertThatCode(() -> {
      try (ConfigurableApplicationContext context = new SpringApplicationBuilder(ExcludedApp.class)
          .properties("spring.autoconfigure.exclude="
              + "com.codeheadsystems.hofmann.springboot.config.HofmannAutoConfiguration",
              "server.port=0")
          .web(org.springframework.boot.WebApplicationType.SERVLET)
          .run()) {
        assertThat(context.isActive()).isTrue();
      }
    }).doesNotThrowAnyException();
  }

  @SpringBootApplication
  static class ExcludedApp {
  }
}
