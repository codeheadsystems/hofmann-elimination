# Security Notes

## CSRF Disabled in HofmannSecurityConfig

`hofmann-springboot/src/main/java/com/codeheadsystems/hofmann/springboot/security/HofmannSecurityConfig.java`

CSRF protection is intentionally disabled. This API is stateless (JWT bearer tokens, no session
cookies), so CSRF does not apply:

- No session cookies means browsers have nothing to automatically attach to cross-origin requests.
- Cross-origin attackers cannot read or forge the `Authorization` header carrying the JWT.
- Enabling CSRF would break all clients (including `hofmann-client`) that do not send a CSRF token.

The combination of `SessionCreationPolicy.STATELESS` + JWT filter + CSRF disabled is the standard
Spring Security configuration for a pure REST API.
