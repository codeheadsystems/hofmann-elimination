package com.codeheadsystems.hofmann.testserver;

import com.codeheadsystems.hofmann.dropwizard.HofmannBundle;
import com.codeheadsystems.hofmann.dropwizard.HofmannConfiguration;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;

/**
 * Runnable Dropwizard application for local developer testing of OPAQUE and OPRF clients.
 * Uses in-memory credential and session stores; all data is lost on restart.
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
    bootstrap.addBundle(new HofmannBundle<>());
  }

  @Override
  public void run(HofmannConfiguration configuration, Environment environment) {
    // Protected endpoint: verifies that OPAQUE registration + authentication
    // produces a valid JWT that grants access to downstream resources.
    environment.jersey().register(new WhoAmIResource());
  }
}
