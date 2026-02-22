package com.codeheadsystems.hofmann.springboot;

import com.codeheadsystems.hofmann.springboot.security.HofmannPrincipal;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The type Who am i controller.
 */
@RestController
@RequestMapping("/api/whoami")
public class WhoAmIController {

  /**
   * Who am i map.
   *
   * @param principal the principal
   * @return the map
   */
  @GetMapping
  public Map<String, String> whoAmI(@AuthenticationPrincipal HofmannPrincipal principal) {
    return Map.of("credentialIdentifier", principal.credentialIdentifier());
  }
}
