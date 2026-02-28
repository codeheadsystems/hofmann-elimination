# the Hofmann Elimination

## tl;dr

This project implements the OPRF and OPAQUE security protocols to provide a way
for common services to reduce their attack surfaces including offline attacks
from stolen credentials. Usable with standard frameworks like Dropwizard and Spring Boot.


## Module Structure

![the Hofmann Elimination Build](https://github.com/codeheadsystems/hofmann-elimination/actions/workflows/gradle.yml/badge.svg)

### Java / Server-side (Maven artifacts)

| -- Artifact ID       | Version                                                                                                                                                                                                                        | Description                                                                                                    |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `hofmann-rfc`        | [![Maven Central: hofmann-rfc](https://img.shields.io/maven-central/v/com.codeheadsystems/hofmann-rfc?label=hofmann-rfc)](https://central.sonatype.com/artifact/com.codeheadsystems/hofmann-rfc)                               | All RFC implementations: hash-to-curve (RFC 9380), OPRF (RFC 9497), OPAQUE (RFC 9807), plus shared model DTOs. |
| `hofmann-client`     | [![Maven Central: hofmann-client](https://img.shields.io/maven-central/v/com.codeheadsystems/hofmann-client?label=hofmann-client)](https://central.sonatype.com/artifact/com.codeheadsystems/hofmann-client)                   | Client files needed for OPRF/OPAQUE integration.                                                               |
| `hofmann-server`     | [![Maven Central: hofmann-server](https://img.shields.io/maven-central/v/com.codeheadsystems/hofmann-server?label=hofmann-server)](https://central.sonatype.com/artifact/com.codeheadsystems/hofmann-server)                   | Server files needed for OPRF/OPAQUE integration.                                                               |
| `hofmann-dropwizard` | [![Maven Central: hofmann-dropwizard](https://img.shields.io/maven-central/v/com.codeheadsystems/hofmann-dropwizard?label=hofmann-dropwizard)](https://central.sonatype.com/artifact/com.codeheadsystems/hofmann-dropwizard)   | Integration files specific for Dropwizard.                                                                     |
| `hofmann-springboot` | [![Maven Central: hofmann-springboot](https://img.shields.io/maven-central/v/com.codeheadsystems/hofmann-springboot?label=hofmann-springboot)](https://central.sonatype.com/artifact/com.codeheadsystems/hofmann-springboot)   | Integration files specific for Spring Boot.                                                                    |

### TypeScript / Browser client

| Directory              | Description                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------|
| [`hofmann-typescript`](hofmann-typescript/README.md) | Browser/Node TypeScript client — RFC 9497 OPRF + RFC 9807 OPAQUE-3DH. Built on `@noble/curves` and `@noble/hashes`. Includes a Vite-powered interactive demo page. |

### Demo environment

| Directory              | Description                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------|
| [`hofmann-demo`](hofmann-demo/README.md) | Docker Compose environment running the Dropwizard server and the TypeScript demo UI behind HAProxy with TLS 1.3. Self-signed P-256 cert generated via `make certs`. Run with `make up`. |

### Building

#### Java (requires Java 21)

```
./gradlew clean build test
```

#### TypeScript

```
cd hofmann-typescript
npm install
npm test
npm run build
```

## Purpose

This project provides a pure Java implementation of the OPRF and OPAQUE protocols,
enabling services to authenticate users without ever storing or transmitting the
password or private key material. By using OPRF and OPAQUE, services can
significantly reduce the attack surface and protect user credentials even in the
event of a server breach — a compromised server database does not expose passwords
to offline dictionary attacks because the server never holds a recoverable form of
the password.

This project also provides the OPRF primitive on its own. This allows clients
to create identifiers from hashing sensitive material that are consistent and
reusable across multiple clients without sharing that key material that generated
them. The result is an identifier that services can use without learning what
data produced it. Useful when that data is sensitive information the client wants
to keep private.

## Protocols

This project implements three layered RFCs:

- **[RFC 9380 — Hash-to-Curve](hofmann-rfc/HASH_TO_CURVE.md)**: Deterministically maps
  arbitrary input to an elliptic curve point using Simplified SWU and `expand_message_xmd`.
  Used internally by OPRF.

- **[RFC 9497 — OPRF](hofmann-rfc/OPRF.md)**: Oblivious Pseudorandom Functions. The client
  computes a pseudorandom function on private input using the server's secret key, without
  the server ever learning the input. Supports P-256/SHA-256, P-384/SHA-384, P-521/SHA-512,
  and Ristretto255/SHA-512.

- **[RFC 9807 — OPAQUE](hofmann-rfc/OPAQUE.md)**: Augmented Password-Authenticated Key
  Exchange. Password-based authentication where the password is never transmitted and a
  compromised server database does not expose passwords to offline dictionary attacks.

For protocol details, cipher suites, API reference, and wire formats, see the linked docs above.

## Security

As of February 2026, this implementation has not undergone a formal security audit.
See [SECURITY.md](SECURITY.md) for the full security posture, known design decisions,
and how to report vulnerabilities.

Initial RFC implementations were produced with the help of AI tooling and reviewed
against the RFC specifications by a human (Ned). AIs have also been used to search
for direct and side-channel attack vectors, but this is not a substitute for a formal
third-party audit.

## RFC Implementation

This project implements the following RFCs:

- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html): Hashing to Elliptic Curves
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html): Oblivious Pseudorandom Functions (OPRFs)
- [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html): OPAQUE: An Asymmetric PAKE Protocol

## Related Projects

Several other projects implement OPRF or OPAQUE, but none cover the same combination
of pure Java, final RFC compliance, P-256/SHA-256, and framework integration.

### aldenml/ecc (`org.ssohub:ecc`)

- **URL**: https://github.com/aldenml/ecc
- **Language**: Java bindings over a C core (JNI)
- **Protocols**: Pre-RFC OPRF (draft-irtf-cfrg-voprf-21) and pre-RFC OPAQUE (draft-irtf-cfrg-opaque-12)
- **Cipher suite**: Ristretto255/SHA-512 only
- **Status**: Stale — last release October 2023; has not tracked RFC 9497 or RFC 9807

### stef/libopaque

- **URL**: https://github.com/stef/libopaque
- **Language**: C core with Java JNI bindings
- **Protocols**: Pre-RFC OPAQUE draft; Ristretto25519 with Argon2id via libsodium
- **Cipher suite**: Ristretto25519/SHA-512; does not support P-256
- **Status**: Actively maintained (v1.0.1, February 2025), but requires manual native compilation
  of libsodium and libopaque — cannot be distributed as a self-contained JAR

### bytemare/opaque (Go)

- **URL**: https://github.com/bytemare/opaque
- **Language**: Go
- **Protocols**: RFC 9497 OPRF + RFC 9807 OPAQUE (written by an RFC co-author; most compliant
  implementation found)
- **Cipher suites**: P256-SHA256, P384-SHA512, P521-SHA512, Ristretto255-SHA512
- **Status**: Actively maintained; no Java bindings

### oprf4j (pvriel/oprf4j)

- **URL**: https://github.com/pvriel/oprf4j
- **Language**: Pure Java
- **Protocols**: Research-paper OPRF variants (KISS17, KALES19) for private set intersection —
  not the IETF OPRF standard
- **Status**: Archived May 2025; PhD research artifact only

### facebook/opaque-ke (Rust)

- **URL**: https://github.com/facebook/opaque-ke
- **Language**: Rust
- **Protocols**: Pre-RFC OPAQUE draft; Ristretto255 only
- **Status**: Actively maintained; no Java bindings

### How This Project Differs

| Property               | This project                                    | aldenml/ecc        | stef/libopaque     | bytemare/opaque       |
|------------------------|-------------------------------------------------|--------------------|--------------------|-----------------------|
| Language               | Pure Java                                       | Java/JNI over C    | Java/JNI over C    | Go                    |
| RFC 9497 OPRF          | Yes                                             | No (pre-RFC draft) | No (pre-RFC draft) | Yes                   |
| RFC 9807 OPAQUE        | Yes                                             | No (pre-RFC draft) | No (pre-RFC draft) | Yes                   |
| Cipher suite           | P-256/SHA-256, P-384/SHA-384, P-521/SHA-512     | Ristretto255       | Ristretto25519     | Multiple incl. P-256  |
| Self-contained JAR     | Yes                                             | Yes (JNI)          | No (native deps)   | N/A                   |
| Maven/Gradle artifact  | Yes (planned)                                   | Yes                | No                 | N/A                   |
| Framework integrations | Dropwizard, Spring Boot                         | None               | None               | None                  |

The closest equivalent in terms of RFC compliance and P-256 support is `bytemare/opaque`,
but it targets Go. This project is the only known pure-Java, RFC-compliant (9380 + 9497 + 9807)
implementation using P-256/SHA-256 that is distributable as a standard Maven artifact.

## License

Copyright 2026 Ned Wolpert

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Origins of the name

The [Hofmann Elimination](https://en.wikipedia.org/wiki/Hofmann_elimination) is a chemical reaction that involves the elimination of an
 amine to produce an alkene. This reaction is named after the German chemist August
Wilhelm von Hofmann, who first described it in the 19th century. The Hofmann elimination
is often used to synthesize alkenes from amines. It does this by treating the quaternary
ammonium salt with a strong base, such as sodium hydroxide, which leads to the elimination
of the ammonium group and the formation of an alkene. The reaction is typically carried out
under heat to facilitate the elimination process.

Unlike other elimination reactions, the Hofmann elimination produces the least substituted
alkene as the major product, which is a result of the steric hindrance around the quaternary
ammonium salt. This makes it a useful reaction for synthesizing specific alkenes that may be
difficult to obtain through other methods.

Just as the Hofmann elimination removes an amine group from a molecule, leaving no trace
of the original nitrogen compound in the product, this protocol eliminates the password
and private key material from every value that leaves the client. The server evaluates the
function, stores credentials, and verifies authentication without ever seeing the sensitive input.
