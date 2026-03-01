package com.codeheadsystems.hofmann.integration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Minimal Spring Boot application for integration tests.
 * Scans the hofmann-springboot package for controllers and security config,
 * plus this package for test-only controllers (WhoAmIController).
 * HofmannAutoConfiguration is pulled in via spring.factories auto-configuration.
 */
@SpringBootApplication(scanBasePackages = {
    "com.codeheadsystems.hofmann.springboot",
    "com.codeheadsystems.hofmann.integration"
})
public class IntegrationTestApplication {

  public static void main(String[] args) {
    SpringApplication.run(IntegrationTestApplication.class, args);
  }
}
