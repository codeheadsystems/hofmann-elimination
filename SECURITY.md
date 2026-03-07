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
- https://github.com/codeheadsystems/hofmann-elimination/security/advisories/new

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

### TLS Required for Production

OPAQUE eliminates password exposure at the protocol level, but the HTTP messages
themselves — blinded OPRF elements, masked envelopes, MACs, JWTs — must still be
protected in transit. **All production deployments MUST use HTTPS (TLS 1.2+, preferably
TLS 1.3).**

Without TLS, an active network attacker can:

- **Steal JWTs** returned by `/opaque/auth/finish` and impersonate the user.
- **Replay or tamper with KE1/KE2/KE3 messages**, potentially disrupting the handshake.
- **Observe credential identifiers** in registration and authentication requests,
  enabling user enumeration despite the protocol's built-in resistance.

OPAQUE's cryptographic properties (zero password exposure, offline attack resistance)
remain intact even without TLS — the password is never recoverable from the wire
traffic. However, session tokens and protocol messages are not encrypted by OPAQUE
itself, so TLS is essential for a complete security posture.

#### Deployment patterns

Most deployments terminate TLS at a reverse proxy rather than in the Java application:

| Pattern | Example | Notes |
|---------|---------|-------|
| Reverse proxy | HAProxy, nginx, Caddy, Envoy | Recommended. The `hofmann-demo` uses HAProxy with TLS 1.3. |
| Cloud load balancer | AWS ALB, GCP HTTPS LB, Azure App Gateway | TLS is terminated at the LB; traffic to the app is plaintext on a private network. |
| Application-level TLS | Dropwizard HTTPS connector, Spring Boot `server.ssl.*` | Viable for single-instance deployments; adds certificate management complexity. |

The Hofmann library does not configure TLS itself because TLS termination is an
infrastructure concern that varies by deployment. Ensure that whatever layer terminates
TLS is configured with strong cipher suites and valid certificates.

### Argon2id KSF Runs on the Client

The Argon2id key-stretching function runs entirely on the client, not the server. The server
stores only the already-stretched output inside the OPAQUE envelope and masking key. This
means the server never performs expensive password hashing — and also means the client and
server must be configured with matching Argon2id parameters. See [USAGE.md](USAGE.md) for details.

### Constant-Time MAC Verification

MAC comparisons in the OPAQUE AKE (`serverFinish`, internal AKE verification) use
`MessageDigest.isEqual()` to prevent timing-based oracle attacks.

---

## Known Concerns with the OPAQUE Protocol

The following are known limitations and criticisms of the OPAQUE protocol itself (not
specific to this implementation). They are documented here so that adopters can make
informed decisions.

### No quantum resistance

OPAQUE relies on elliptic curve discrete log hardness (ECDH) for both the OPRF and
the 3DH authenticated key exchange. A sufficiently powerful quantum computer running
Shor's algorithm would break these primitives. Post-quantum PAKE protocols are an
active research area but none have been standardized. If quantum resistance is a
requirement today, OPAQUE is not the right choice.

### OPRF key is a high-value target

If the server's OPRF key is compromised *alongside* the credential database, offline
dictionary attacks become possible again. OPAQUE does not eliminate the need to protect
server secrets — it changes *what* needs protecting. The improvement over traditional
hashing is that the OPRF key and the credential records can be stored separately (e.g.,
the key in an HSM, the records in a database), whereas traditional password hashes are
self-contained attack targets. This separation requires operational discipline.

### No protection against online brute force

OPAQUE prevents *offline* dictionary attacks from a stolen credential database. An
attacker with network access can still try passwords one at a time through the live
protocol. Rate limiting on authentication endpoints is still essential.

### Limited phishing resistance

OPAQUE provides mutual authentication — both client and server prove their identity
during the handshake. However, it does not protect against real-time phishing proxies
that relay the full protocol between the victim and the legitimate server.
FIDO2/WebAuthn provides stronger phishing resistance through cryptographic origin
binding. OPAQUE and WebAuthn solve different problems and can be complementary.

### Browser trust model undermines some guarantees

For browser-based clients, the JavaScript performing the OPAQUE protocol is served by
the server itself. A compromised server could serve malicious code that exfiltrates the
password before blinding it. This "trust the server to serve honest code" problem
affects all browser-based cryptography and is not specific to OPAQUE, but it means
OPAQUE's strongest guarantees (password never leaves the client) only hold fully for
native or pre-installed clients.

### Client-side computation cost

OPAQUE requires the client to perform elliptic curve scalar multiplications and
(typically) Argon2id key stretching. On resource-constrained mobile devices or low-end
browsers, production-grade Argon2id parameters (64+ MiB memory, 3 iterations) can cause
noticeable latency or memory pressure. Tuning KSF parameters is a trade-off between
security and user experience.

### No traditional password recovery

Since the server never sees the password, traditional "forgot password" flows that
verify the old credential are not possible. Password reset requires re-registration,
which destroys the previous credential record. This is a security feature (the server
*cannot* leak what it does not have) but an operational consideration that affects UX
design. See the [Migration Guide](MIGRATION.md) for strategies.

### Migration requires re-registration

Existing bcrypt, scrypt, or Argon2id password hashes cannot be converted to OPAQUE
credentials. Every user must re-register, either via a forced reset or opportunistic
migration on next login. See the [Migration Guide](MIGRATION.md) for detailed
strategies.

### Increased protocol complexity

OPAQUE involves multiple rounds, multiple cryptographic primitives (OPRF, HKDF, HMAC,
Diffie-Hellman AKE), and subtle security invariants. More complexity means more surface
area for implementation bugs compared to "hash and compare." Fewer implementations have
been battle-tested or formally audited compared to bcrypt or Argon2id.

### Small ecosystem

Compared to traditional authentication (bcrypt, OAuth 2.0, OpenID Connect), the OPAQUE
ecosystem has far fewer implementations, fewer independent security audits, and less
accumulated operational experience across the industry. See the
[Related Projects](https://codeheadsystems.github.io/hofmann-elimination/) section for
a comparison of available implementations.
