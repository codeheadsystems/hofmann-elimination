package com.codeheadsystems.hofmann.dropwizard;

import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;

/**
 * Minimal Dropwizard application used only in integration tests.
 * Not part of the library's public API.
 */
public class HofmannApplication extends Application<HofmannConfiguration> {

  /**
   * The entry point of application.
   *
   * @param args the input arguments
   * @throws Exception the exception
   */
  public static void main(String[] args) throws Exception {
    new HofmannApplication().run(args);
  }

  @Override
  public String getName() {
    return "hofmann-test";
  }

  @Override
  public void initialize(Bootstrap<HofmannConfiguration> bootstrap) {
    bootstrap.addBundle(new HofmannBundle<>());
  }

  @Override
  public void run(HofmannConfiguration configuration, Environment environment) {
    // Register a test-only protected endpoint to exercise JWT auth in integration tests
    environment.jersey().register(new WhoAmIResource());
  }
}
