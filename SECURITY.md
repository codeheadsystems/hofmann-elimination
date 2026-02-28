# Security Notes

## Audit Status

As of February 2026, this implementation has **not undergone a formal security audit** by a
reputable third party.

The RFC implementations have been validated against the official test vectors published in each
RFC appendix, and against the CFRG reference implementations. All RFC code has been reviewed
and verified against the specifications by a human. OPAQUE in particular warrants further review
before production use in high-stakes environments.

AI tooling has been used to search for direct and side-channel attack vectors, but AI review is
not a substitute for a formal third-party audit.

Use in production is at your own risk. A formal security audit is planned but not yet scheduled.

---

## Reporting Vulnerabilities

If you discover a security vulnerability, please **do not open a public GitHub issue**.

Report privately via GitHub's security advisory workflow:
- https://github.com/wolpert/hofmann-elimination/security/advisories/new

Or contact the maintainer directly at: ned.wolpert@gmail.com

Please include:
- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The affected component(s) and version(s)
- Your assessment of severity

You will receive an acknowledgement within 72 hours. Patches for confirmed vulnerabilities
will be released as soon as possible, with a coordinated disclosure timeline agreed with the
reporter.

---

## Known Design Decisions

### CSRF Disabled in HofmannSecurityConfig

`hofmann-springboot/src/main/java/com/codeheadsystems/hofmann/springboot/security/HofmannSecurityConfig.java`

CSRF protection is intentionally disabled. This API is stateless (JWT bearer tokens, no session
cookies), so CSRF does not apply:

- No session cookies means browsers have nothing to automatically attach to cross-origin requests.
- Cross-origin attackers cannot read or forge the `Authorization` header carrying the JWT.
- Enabling CSRF would break all clients (including `hofmann-client`) that do not send a CSRF token.

The combination of `SessionCreationPolicy.STATELESS` + JWT filter + CSRF disabled is the standard
Spring Security configuration for a pure REST API.

### Argon2id KSF Runs on the Client

The Argon2id key-stretching function runs entirely on the client, not the server. The server
stores only the already-stretched output inside the OPAQUE envelope and masking key. This
means the server never performs expensive password hashing — and also means the client and
server must be configured with matching Argon2id parameters. See [USAGE.md](USAGE.md) for details.

### Constant-Time MAC Verification

MAC comparisons in the OPAQUE AKE (`serverFinish`, internal AKE verification) use
`MessageDigest.isEqual()` to prevent timing-based oracle attacks.
