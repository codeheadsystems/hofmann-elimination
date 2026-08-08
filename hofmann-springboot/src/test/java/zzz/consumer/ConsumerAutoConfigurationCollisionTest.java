package zzz.consumer;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.web.SecurityFilterChain;

/**
 * A consumer contributing the chain from their own {@code @AutoConfiguration}.
 *
 * <p><strong>The package name is the test.</strong> {@code AutoConfigurationSorter} orders
 * auto-configurations by full class name before applying before/after, so whether the library's
 * chain or the consumer's was evaluated first came down to the alphabet:
 * {@code com.aaa.SomeAutoConfiguration} booted, {@code zzz.consumer.…} died with
 * {@code UnreachableFilterChainException}. Identical code, different package. {@code zzz} is
 * chosen to sort after {@code com.codeheadsystems}, which is the losing side.
 *
 * <p>{@code @ConditionalOnMissingBean} cannot fix this — a condition only sees what earlier
 * auto-configurations contributed — and neither can ordering, since {@code @AutoConfigureOrder}
 * already defaults to {@code LOWEST_PRECEDENCE} and there is nothing later to ask for. The
 * {@code BeanFactoryPostProcessor} in {@code HofmannSecurityConfig} decides it after every
 * definition exists, which makes the answer independent of arrival order.
 */
class ConsumerAutoConfigurationCollisionTest {

  @SpringBootApplication
  @ImportAutoConfiguration(LateSortingConsumerAutoConfiguration.class)
  static class ConsumerApp {
  }

  @SpringBootApplication
  @ImportAutoConfiguration(NameClashConsumerAutoConfiguration.class)
  static class NameClashApp {
  }

  private ConfigurableApplicationContext boot() {
    return boot(ConsumerApp.class);
  }

  private ConfigurableApplicationContext boot(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .properties("hofmann.oprf-master-key-hex=2a",
            "hofmann.jwt-secret-hex=" + "ab".repeat(32),
            "hofmann.server-key-seed-hex=" + "cd".repeat(32),
            "hofmann.oprf-seed-hex=" + "ef".repeat(32),
            "server.port=0")
        .web(WebApplicationType.SERVLET)
        .run();
  }

  @Test
  void theLibraryChainStandsDownForAConsumerAutoConfiguration() {
    try (ConfigurableApplicationContext context = boot()) {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .as("two chains here means UnreachableFilterChainException, which is how this failed")
          .containsExactly("appSecurity");
    }
  }

  /**
   * A consumer naming their chain {@code securityFilterChain} must start.
   *
   * <p>This did not collide — it failed outright with {@code BeanDefinitionOverrideException},
   * and the post-processor structurally cannot help, because registration is where it dies. The
   * library's chain is named {@code hofmannSecurityFilterChain} for exactly this reason, which is
   * the same argument already made for {@code hofmannCorsConfigurationSource} and simply not
   * applied here until a reviewer pointed at it.
   */
  @Test
  void aConsumerMayNameTheirChainSecurityFilterChain() {
    try (ConfigurableApplicationContext context = boot(NameClashApp.class)) {
      assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
          .containsExactly("securityFilterChain");
    }
  }

  /** The library's own beans must survive the withdrawal — only the chain is retracted. */
  @Test
  void theJwtFilterSurvivesTheWithdrawal() {
    try (ConfigurableApplicationContext context = boot()) {
      assertThat(context.getBeanNamesForType(
          com.codeheadsystems.hofmann.springboot.security.JwtAuthenticationFilter.class))
          .hasSize(1);
    }
  }
}
