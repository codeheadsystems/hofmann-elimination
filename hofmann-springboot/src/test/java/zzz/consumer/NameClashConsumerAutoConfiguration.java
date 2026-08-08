package zzz.consumer;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * A consumer auto-configuration naming its chain {@code securityFilterChain} — the name Spring
 * Boot's own reference documentation uses, and therefore the one a consumer reaches for.
 */
@AutoConfiguration
public class NameClashConsumerAutoConfiguration {
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
  }
}
