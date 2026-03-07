# PRFAQ: Hofmann Elimination

## Press Release

### Hofmann Elimination: Open-Source OPAQUE Password Authentication for Java

*Drop-in Spring Boot and Dropwizard library eliminates password exposure from server breaches*

**OPEN SOURCE — March 2026** — Today, the Hofmann Elimination project announces
general availability of the first pure-Java implementation of the OPAQUE
password authentication protocol (RFC 9807). Hofmann Elimination enables Java
services to authenticate users without the server ever receiving, storing, or
being able to recover the user's password. Published to Maven Central, the
library integrates with Spring Boot and Dropwizard in a single dependency.

**The problem.** Every year, billions of credentials are exposed in database
breaches. Traditional password authentication — even with modern hashing
algorithms like bcrypt, scrypt, or Argon2id — stores a value on the server that
an attacker can run offline dictionary attacks against. Once an attacker has the
database, they have unlimited time and compute to crack passwords. Stronger hash
functions slow these attacks but do not prevent them. The fundamental issue is
that the server holds enough information to verify password guesses.

**The solution.** OPAQUE is an asymmetric Password-Authenticated Key Exchange
(aPAKE) protocol standardized by the IETF in RFC 9807. It uses an Oblivious
Pseudorandom Function (OPRF) so that the password is processed cryptographically
on the client side but never transmitted to the server. The server stores only
cryptographic values that are bound to a separate OPRF secret key. Even if the
entire credential database is stolen, an attacker cannot run offline dictionary
attacks because the stored records are useless without the OPRF key — and the
OPRF key can be stored separately in an HSM or key management service.

"Password breaches remain the most common and damaging attack vector on the
internet. OPAQUE has been an IETF standard since 2025, but adoption has been
held back by the lack of production-ready Java implementations," said Ned
Wolpert, creator of the Hofmann Elimination project. "We built this library so
that any Java team can upgrade from 'hash and compare' to 'the server never sees
the password' by adding one Gradle dependency and a few lines of YAML
configuration."

**How it works.** A developer adds `hofmann-springboot` or `hofmann-dropwizard`
to their build file. The framework starter auto-configures all OPAQUE and OPRF
REST endpoints. On the client side, the TypeScript library (or the Java client)
handles the full OPAQUE handshake: blinding the password, performing the OPRF
exchange, deriving keys, sealing the credential envelope during registration,
and recovering it during authentication. The server never sees the password at
any point. After a successful authentication, the server issues a JWT for
subsequent API calls. The entire integration requires no changes to existing
business logic — only the authentication layer is replaced.

"We evaluated OPAQUE after our third credential rotation incident in two years.
The idea that a database breach simply cannot expose passwords — not 'it would
take a long time to crack them,' but 'there is nothing to crack' — was exactly
what we needed. Hofmann Elimination was the only option that worked with our
Spring Boot stack without requiring native libraries or a language change," said
a principal engineer at an early-adopter organization.

**Getting started.** Hofmann Elimination is open source under the Apache 2.0
license and available on Maven Central. Add the Spring Boot starter or
Dropwizard bundle, configure your OPRF key and server seed, and the OPAQUE
endpoints are live. A complete example application, migration guide, interactive
API documentation, and Docker-based demo environment are available at
https://codeheadsystems.github.io/hofmann-elimination/.

---

## Frequently Asked Questions

### External FAQ (Customer / Adopter)

**Q: What problem does Hofmann Elimination solve?**

A: Traditional password authentication stores a hash of the user's password on
the server. If the database is breached, attackers can run offline dictionary
attacks against those hashes. Hofmann Elimination implements the OPAQUE protocol
(RFC 9807), which ensures the server never receives or stores the password in any
form that can be attacked offline. A stolen credential database is
cryptographically useless to an attacker without the server's separate OPRF
secret key.

**Q: How is this different from just using bcrypt or Argon2id?**

A: Bcrypt and Argon2id are password hashing functions that make offline attacks
*slower*. OPAQUE makes offline attacks *impossible* (without the OPRF key). With
bcrypt, a stolen database gives an attacker everything they need — it is only a
matter of time and compute. With OPAQUE, a stolen database gives the attacker
values that are bound to a secret key stored elsewhere. The two approaches are
complementary: Hofmann Elimination uses Argon2id *inside* the OPAQUE protocol as
a client-side key-stretching function, adding defense in depth.

**Q: Does the password ever leave the user's device?**

A: No. The password is used on the client to blind an OPRF input, derive
cryptographic keys, and seal/unseal an envelope. Only blinded values and
cryptographic protocol messages are sent over the wire. The server processes
these messages using its OPRF key and stored credential records, but it cannot
recover the password from them.

**Q: What frameworks and languages are supported?**

A: The server side is pure Java 21 with drop-in starters for Spring Boot and
Dropwizard. The client side is available as a TypeScript library (browser and
Node.js) and a Java client library. The protocol is standard REST over HTTPS, so
clients in any language can be built against the OpenAPI specification.

**Q: What cipher suites are supported?**

A: P-256/SHA-256, P-384/SHA-384, P-521/SHA-512, and Ristretto255/SHA-512. The
server and client auto-negotiate the cipher suite via the `/opaque/config`
endpoint. P-256/SHA-256 is the RFC 9807 reference suite and the default.

**Q: How do I migrate an existing application that uses bcrypt/scrypt?**

A: Existing password hashes cannot be converted to OPAQUE credentials — users
must re-register. The project includes a [Migration Guide](MIGRATION.md)
covering three strategies: forced migration (reset all passwords at once),
opportunistic migration (convert users one at a time on their next login), and
hybrid migration (set a deadline, force-reset users who have not logged in by
then). The guide includes schema changes, pseudocode, and a checklist.

**Q: Does this replace TLS?**

A: No. OPAQUE protects the password, but the HTTP messages (protocol elements,
JWTs) still need transport encryption. All production deployments must use HTTPS.
See [SECURITY.md](SECURITY.md) for details.

**Q: What about "forgot password" flows?**

A: Since the server cannot recover the password, traditional "forgot password"
cannot verify the old credential. Password reset requires deleting the old
OPAQUE credential and re-registering. This can be triggered by an email/SMS
reset link that authenticates the user through a separate channel and then
initiates a new OPAQUE registration.

**Q: Is OPAQUE resistant to phishing?**

A: OPAQUE provides mutual authentication (both client and server prove their
identity), but it does not protect against real-time phishing proxies that relay
the protocol. For stronger phishing resistance with origin binding, consider
FIDO2/WebAuthn. OPAQUE and WebAuthn are complementary and can be used together.

**Q: Is this quantum-resistant?**

A: No. OPAQUE relies on elliptic curve Diffie-Hellman, which is vulnerable to
Shor's algorithm on a sufficiently powerful quantum computer. Post-quantum PAKE
protocols are an active research area but none are standardized. See
[SECURITY.md](SECURITY.md) for a full discussion of known protocol concerns.

**Q: Has this implementation been audited?**

A: As of March 2026, no. The implementation has been validated against all
official RFC test vectors and reviewed for side-channel vulnerabilities, but it
has not undergone a formal third-party security audit. A formal audit is planned
but not yet scheduled. See [SECURITY.md](SECURITY.md) for the full security
posture.

**Q: What credential store backends are supported?**

A: The library ships with an in-memory credential store for development and
testing. For production, you implement the `CredentialStore` interface (two
methods: `store` and `retrieve`) with your preferred database. The example
application demonstrates a database-backed implementation. Spring Boot users can
override the default bean; Dropwizard users pass their store to the
`HofmannBundle` constructor.

**Q: Can I use the OPRF without OPAQUE?**

A: Yes. The standalone OPRF endpoint (`POST /oprf`) is registered alongside the
OPAQUE endpoints. OPRF allows clients to compute a pseudorandom function on
private input using the server's key, without the server learning the input.
This is useful for privacy-preserving identifiers, private set intersection, and
token derivation.

---

### Internal FAQ (Technical / Stakeholder)

**Q: Why pure Java instead of wrapping a C or Rust library?**

A: JNI-based libraries (aldenml/ecc, stef/libopaque) require native compilation,
platform-specific binaries, and complicate deployment in containerized
environments. A pure Java implementation distributes as a standard Maven
artifact, works on any JVM platform without native dependencies, and is
auditable by Java security teams without requiring C or Rust expertise.
BouncyCastle provides the underlying elliptic curve arithmetic.

**Q: Why implement three RFCs instead of just OPAQUE?**

A: OPAQUE (RFC 9807) depends on OPRF (RFC 9497), which depends on Hash-to-Curve
(RFC 9380). No existing Java library implemented these three RFCs in their final,
published form. Implementing the full stack ensures correctness against the
official test vectors at every layer and avoids depending on pre-RFC draft
implementations that may have incompatible wire formats.

**Q: What is the performance overhead compared to bcrypt?**

A: The server-side cost is lower than bcrypt because the expensive key-stretching
(Argon2id) runs on the client. The server performs one OPRF evaluation (an EC
scalar multiplication) and one 3DH key exchange per authentication. On the
client, the Argon2id cost depends on the configured parameters. With the default
parameters (64 MiB, 3 iterations), client-side key stretching takes 200-800ms
depending on the device.

**Q: What happens if the OPRF key is compromised?**

A: If the OPRF key is compromised alongside the credential database, offline
dictionary attacks become possible — the attacker can evaluate the OPRF locally
and test passwords. The mitigation is to store the OPRF key separately from the
credential database (HSM, key management service, separate infrastructure). This
separation is not possible with traditional password hashing, where the hash
itself is the complete attack target.

**Q: How are the framework starters tested?**

A: The `hofmann-integration-tests` module runs full OPAQUE registration and
authentication flows across all four cipher suites (P-256, P-384, P-521,
Ristretto255) with Argon2id enabled. Cross-client tests exercise the Java
client against the TypeScript client to verify interoperability. All tests run
in CI on every commit.

**Q: What is the risk of protocol-level vulnerabilities?**

A: OPAQUE has formal security proofs in the academic literature (Jarecki et al.,
Eurocrypt 2018) and has been standardized through the IETF process with
multi-year review. The protocol is sound. The risk lies in implementation
correctness — translating the mathematical specification into code without
introducing bugs. This risk is mitigated by test vector validation, constant-time
operations for MAC comparison and scalar serialization, and explicit zeroing of
intermediate key material. A formal audit would further reduce this risk.

**Q: What are the ongoing maintenance costs?**

A: The library tracks three finalized RFCs that are unlikely to change. Ongoing
maintenance consists of dependency updates (BouncyCastle, framework versions),
responding to security reports, and potentially adding new cipher suites if the
IETF standardizes them. The protocol itself is stable.

**Q: Why not use WebAuthn/FIDO2 instead?**

A: WebAuthn and OPAQUE solve different problems. WebAuthn eliminates passwords
entirely in favor of public-key credentials (hardware keys, biometrics). OPAQUE
keeps the password-based UX that users are familiar with while eliminating the
server's ability to see or leak the password. OPAQUE is a better fit when:
passwords are a business requirement, hardware tokens cannot be mandated, or the
service needs to support environments where WebAuthn is not available. The two
protocols can coexist — OPAQUE for password-based login, WebAuthn as an
optional upgrade.

**Q: What would a formal security audit cover?**

A: An audit should cover: (1) correctness of the RFC 9380/9497/9807
implementations against the specifications, (2) side-channel resistance
(constant-time comparisons, scalar serialization, key material zeroing),
(3) integration security (JWT handling, session management, input validation,
HTTP security headers), and (4) the credential store interface contract to
ensure implementors cannot accidentally introduce vulnerabilities. The estimated
scope is 2-3 weeks for a qualified cryptographic auditing firm.
