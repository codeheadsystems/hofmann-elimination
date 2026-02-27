package com.codeheadsystems.hofmann.testserver;

import com.codeheadsystems.hofmann.dropwizard.HofmannBundle;
import com.codeheadsystems.hofmann.dropwizard.HofmannConfiguration;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;

/**
 * Runnable Dropwizard application for local developer testing of OPAQUE and OPRF clients.
 * Uses in-memory credential and session stores (data lost on restart), but reads the OPRF
 * master key and all other key material from {@code config/config.yml} so that OPRF hashes
 * are stable across restarts as long as the configured keys do not change.
 * Start via Docker Compose from the hofmann-testserver directory.
 */
public class HofmannTestServerApplication extends Application<HofmannConfiguration> {

  /**
   * The entry point of application.
   *
   * @param args the input arguments
   * @throws Exception the exception
   */
  public static void main(String[] args) throws Exception {
    new HofmannTestServerApplication().run(args);
  }

  @Override
  public String getName() {
    return "hofmann-testserver";
  }

  @Override
  public void initialize(Bootstrap<HofmannConfiguration> bootstrap) {
    // Allow ${ENV_VAR:-default} substitution in config YAML files so Docker
    // environment variables can override individual keys without replacing the
    // entire config file.
    bootstrap.setConfigurationSourceProvider(
        new SubstitutingSourceProvider(
            bootstrap.getConfigurationSourceProvider(),
            new EnvironmentVariableSubstitutor(false)
        )
    );
    // Use the 3-arg constructor (not the no-arg one) so ephemeralKey stays false.
    // With ephemeralKey=false and a null processorDetailSupplier, HofmannBundle reads
    // oprfMasterKeyHex from configuration — giving stable OPRF hashes across restarts.
    // Credentials and sessions still live in memory and are lost on restart.
    bootstrap.addBundle(new HofmannBundle<>(
        new InMemoryCredentialStore(),
        new InMemorySessionStore(),
        null));
  }

  @Override
  public void run(HofmannConfiguration configuration, Environment environment) {
    // Protected endpoint: verifies that OPAQUE registration + authentication
    // produces a valid JWT that grants access to downstream resources.
    environment.jersey().register(new WhoAmIResource());
  }
}
