package com.codeheadsystems.hofmann.springboot.security;

import com.codeheadsystems.hofmann.server.auth.JwtManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The type Jwt authentication filter.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtManager jwtManager;

  /**
   * Instantiates a new Jwt authentication filter.
   *
   * @param jwtManager the jwt manager
   */
  public JwtAuthenticationFilter(JwtManager jwtManager) {
    this.jwtManager = jwtManager;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
    String authHeader = request.getHeader("Authorization");
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      String token = authHeader.substring(7);
      jwtManager.verify(token).ifPresent(result -> {
        HofmannPrincipal principal = new HofmannPrincipal(result.subject(), result.jti());
        UsernamePasswordAuthenticationToken auth =
            new UsernamePasswordAuthenticationToken(principal, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
      });
    }
    filterChain.doFilter(request, response);
  }
}
