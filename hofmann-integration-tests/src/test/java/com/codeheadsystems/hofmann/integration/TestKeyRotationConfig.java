package com.codeheadsystems.hofmann.integration;

import com.codeheadsystems.rfc.opaque.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Test configuration that provides a mutable {@link MutableKeyDetailSupplier},
 * allowing key rotation tests to swap keys mid-test.
 * <p>
 * The {@code @Primary} annotation ensures this overrides the auto-configured
 * {@code Supplier<OpaqueServerKeyDetail>} from {@code HofmannAutoConfiguration}.
 * Since {@code MutableKeyDetailSupplier} implements {@code Supplier<OpaqueServerKeyDetail>},
 * it satisfies all injection points that require the supplier.
 * <p>
 * For non-rotation tests this is transparent: the initial state (version 0, same server)
 * is identical to the default behavior.
 */
@Configuration
class TestKeyRotationConfig {

  @Bean
  @Primary
  MutableKeyDetailSupplier mutableKeyDetailSupplier(Server server) {
    return new MutableKeyDetailSupplier(server);
  }
}
