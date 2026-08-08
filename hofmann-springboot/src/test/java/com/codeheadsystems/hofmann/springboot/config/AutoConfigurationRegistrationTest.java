package com.codeheadsystems.hofmann.springboot.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.springboot.controller.OpaqueController;
import com.codeheadsystems.hofmann.springboot.controller.OprfController;
import com.codeheadsystems.hofmann.springboot.health.OpaqueServerHealthIndicator;
import com.codeheadsystems.hofmann.springboot.security.HofmannSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The auto-configuration registered only {@code HofmannAutoConfiguration}, which carried no
 * {@code @Import} or {@code @ComponentScan} — so the controllers, the security config and the
 * health indicator loaded only if the consumer's own component scan happened to reach
 * {@code com.codeheadsystems.hofmann.springboot.*}. USAGE.md said autoconfiguration "activates
 * automatically" and never mentioned scanning.
 *
 * <p>The repo's own tests could not detect this: {@code HofmannTestApplication} sits in exactly
 * that package, so the scan always found them. These tests deliberately use a context with NO
 * component scanning at all, so they fail if the {@code @Import} is dropped.
 */
class AutoConfigurationRegistrationTest {

  private static final String[] REQUIRED_PROPERTIES = {
      "hofmann.oprf-master-key-hex=2a",
      "hofmann.jwt-secret-hex=" + "ab".repeat(32),
      "hofmann.server-key-seed-hex=" + "cd".repeat(32),
      "hofmann.oprf-seed-hex=" + "ef".repeat(32),
  };

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(HofmannAutoConfiguration.class,
          com.codeheadsystems.hofmann.springboot.security.HofmannSecurityConfig.class))
      .withPropertyValues(REQUIRED_PROPERTIES);

  @Test
  void componentsLoadWithoutAnyComponentScanning() {
    runner.run(context -> {
      assertThat(context).hasSingleBean(OpaqueController.class);
      assertThat(context).hasSingleBean(OprfController.class);
      assertThat(context).hasSingleBean(OpaqueServerHealthIndicator.class);
      assertThat(context).hasSingleBean(SecurityFilterChain.class);
    });
  }

  // The back-off test that used to live here has moved to SecurityChainBackOffTest, which boots
  // real @SpringBootTest contexts.
  //
  // It is not that the old test was redundant — it was actively misleading. ApplicationContextRunner
  // .withUserConfiguration registers user beans directly on the context before refresh, so
  // @ConditionalOnMissingBean sees them and backs off. A real application registers them through
  // the configuration class post-processor instead, where the library's chain was evaluated first,
  // found nothing, and registered itself anyway — leaving the application unable to start with
  // UnreachableFilterChainException. This test reported success on that configuration for as long
  // as it existed. A green test asserting a property the product does not have is worse than no
  // test, because it answers the question nobody re-asks.
  //
  // What remains here is registration wiring, which is what a context runner is good for.

  /** The filter stays available so an application with its own chain can wire it in. */
  @Test
  void jwtFilterRemainsAvailableForApplicationsThatTakeOverSecurity() {
    runner.withUserConfiguration(ApplicationOwnSecurity.class).run(context ->
        assertThat(context).hasSingleBean(
            com.codeheadsystems.hofmann.springboot.security.JwtAuthenticationFilter.class));
  }

  /**
   * A chain matching every request must be published last, or a narrower chain can never be
   * reached. Asserts the relationship rather than the literal, since asserting the constant is
   * non-zero would pass with the {@code @Order} annotation deleted entirely — it would test the
   * constant, not the behaviour.
   */
  @Test
  void catchAllChainIsOrderedLast() {
    assertThat(HofmannSecurityConfig.HOFMANN_CHAIN_ORDER)
        .as("a catch-all chain registered early can shadow a narrower one")
        .isGreaterThan(0)
        .isCloseTo(org.springframework.core.Ordered.LOWEST_PRECEDENCE,
            org.assertj.core.data.Offset.offset(100));
  }

  @Configuration
  static class ApplicationOwnSecurity {
    @Bean
    SecurityFilterChain applicationChain(HttpSecurity http) throws Exception {
      return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
    }
  }
}
