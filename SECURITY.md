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

### Argon2id Runs on the Client, With Server-Supplied Parameters

The Argon2id key-stretching function runs entirely on the client, not the server. The server
stores only the already-stretched output inside the OPAQUE envelope and masking key. This
means the server never performs expensive password hashing — and also means the client and
server must be configured with matching Argon2id parameters. See
[Client configuration](docs/CLIENT_CONFIG.md#argon2id-consistency-between-server-and-client)
for details.

**The client obtains those parameters from the server**, via `GET /opaque/config` and
`OpaqueClientConfig.fromServerConfig`. That is worth stating plainly, because it means a
malicious or compromised server can propose *no key stretching at all* and the client would
otherwise comply — turning a stolen registration record from something requiring an Argon2id
grind per guess into something crackable at the speed of a bare hash. The attack is against the
server's own users, and it is invisible to them.

For that reason the client **throws** rather than warning when the server offers the identity KSF
or parameters outside the accepted window. A warning is no defence when the attacker's own payload
is what triggers it.

The window is enforced at **at least 19456 KiB and 2 iterations** — the OWASP Argon2id minimum at
`t=2, p=1` — and **at most 4 GiB, 10 iterations and 16 lanes**, the upper bounds being
denial-of-service hardening rather than a security floor. Configure the server outside it and every
client throws `IllegalStateException` on first use. `argon2Parallelism` must be `1` for browser
clients, because hash-wasm is single-threaded.

To opt in against a development server deliberately configured with `allowIdentityKsf`, pass
`allowWeakServerKsf` when constructing the client — `new HofmannOpaqueClientManager(accessor,
overrides, true)` in Java, `create(url, { allowWeakServerKsf: true })` in TypeScript. To avoid
negotiating configuration at all, pin an `OpaqueClientConfig` through the manager's overrides map,
which short-circuits before the server is consulted.

**The same endpoint also supplies `context`**, and the manager passes null for both identities — so
`context` is the only deployment-distinguishing value in the AKE preamble, and it is what stops a
transcript from one deployment being replayed against another. If you have it out-of-band, pin it
with the `expectedContext` constructor argument.

### Timing and Side Channels

**Short version:** every scalar multiplication that touches long-term key material runs a
Montgomery ladder — fixed iteration count, no secret-dependent branching. Four known gaps remain,
and all of them need an attacker running code on the same host. **If your deployment does not
share hardware with untrusted tenants, there is nothing here to act on.** If it does, read on —
and do not choose a cipher suite on the strength of this section: the two ladders leak
differently, neither is clearly ahead, and the honest answer is that the difference is
unquantified.

The ladder closes the wNAF leaks that preceded it: digit-dependent add/double sequences, a
precomputed table indexed by secret values, and a window size chosen from the scalar's bit length.

**The ladder's swap differs by suite, and so does what it leaks.** ristretto255 swaps its two
accumulators with a masked XOR (`cswap`) that reads and writes both on every iteration; the
Weierstrass curves index a two-element array by the bit, so which object receives the addition
follows the key. That looks like a point in ristretto255's favour and measurement says otherwise:
`cswap` is built on `BigInteger`, and when the mask is zero the intermediate is `BigInteger.ZERO`
with a zero-length magnitude array while a set bit produces a full-width one — so allocation sizes
track the secret bit. Measured, the masked swap is ~9% slower at a set bit, and end-to-end shows a
slightly *larger* Hamming-weight signal than the indexed accumulator it appears to improve on.

**ristretto255 does not rescale the scalar to a fixed width.** `WeierstrassGroupSpecImpl` rescales
so the loop always runs full-width with the top bit set; ristretto255's ladder starts from the
exact neutral element and runs cheaply while the leading bits are zero. Measured, a 64-bit scalar
completes ~23% faster than a full-length one on ristretto255, where the Weierstrass curves are
flat. This is the residual closest to being remotely observable — it is a static, repeatable bias
against a long-term key on an operation an attacker can trigger without limit — but it discloses
only the leading-zero count of a reduced scalar, one or two bits of 252, so it does not lead to key
recovery.

**Field arithmetic differs too, and here ristretto255 is the weaker one.** The NIST curves resolve
through BouncyCastle's `CustomNamedCurves` to `SecP256R1Curve`/`SecP384R1Curve`/`SecP521R1Curve`,
which use fixed-width `int[]` arithmetic with dedicated reduction — no `BigInteger` in the point
operations at all. ristretto255 implements its field directly as `a.multiply(b).mod(P)`, whose cost
depends on its operands. The Fermat inversion used for scalar inverses is `modPow(n-2, n)`, not
`modInverse`; its exponent is public and fixed-length, so the exponent leaks nothing, but the
secret base flows through unhardened multiplies.

**Fixed-length output is not fixed-time encoding.** `ByteUtils.scalarToFixedBytes` produces a
constant-width result through a `System.arraycopy` whose length is `scalar.toByteArray().length`,
varying with leading zero bytes; `Ristretto255GroupSpec.encodeLittleEndian` has the same shape.
With a *secret* scalar this is reachable only from key generation, once per process — every
per-request caller serializes the proof scalars `c` and `s`, which are published anyway — so it is
not on a path an attacker can measure repeatedly.

None of the four is reachable from the network: all require local code execution on the same host,
and the one with a remote profile discloses at most a couple of bits. There is nothing to
configure for any of them, and no pure-Java fix — constant-time field arithmetic is not something
the JDK offers. See `WeierstrassGroupSpecImpl` and `DleqProver` for the per-site notes.

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
