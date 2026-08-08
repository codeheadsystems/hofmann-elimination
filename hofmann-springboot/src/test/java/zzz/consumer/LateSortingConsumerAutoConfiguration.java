package zzz.consumer;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** Sorts after com.codeheadsystems.* — the case the reviewer said collides. */
@AutoConfiguration
public class LateSortingConsumerAutoConfiguration {
  @Bean
  public SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();
  }
}
