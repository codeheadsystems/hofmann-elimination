# the Hofmann Elimination

## tl;dr

This project implements the OPRF and OPAQUE security protocols to provide a way
for common services to reduce their attack surfaces including offline attacks
from stolen credentials. Usable with standard frameworks like Dropwizard and Spring Boot.


## Module Structure

![the Hofmann Elimination Build](https://github.com/wolpert/hofmann-elimination/actions/workflows/gradle.yml/badge.svg)

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

The implementation covers:
- **RFC 9497** OPRF modes over P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512
  (using RFC 9380 hash-to-curve techniques)
- **RFC 9807** OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE)
  protocol, enabling secure password-based authentication where the password is
  never revealed to the server

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

## RFC Implementation

This project implements the following RFCs:

- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html): Hashing to Elliptic Curves
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html): Oblivious Pseudorandom Functions (OPRFs)
- [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html): OPAQUE: An Asymmetric PAKE Protocol

## Implementation Notes

### ☢ Security Considerations ☢

As of February 2026, This implementation itself has not undergone a formal security audit.

### AI usages

Initial RFC implementations were generated by Ned with the help of AI.
This includes test cases and integrating the RFC test vectors used to validate
the implementations. All RFC code has been reviewed and verified against the RFC
specifications by a human (Ned), though as of February 2026, OPAQUE still needs
further review.  Non-RFC code has been primarily human generated but has help
from AI tooling.

AIs have been, and will continue to be, used to try to find direct or side-channel
attacks. But the AI review is not a substitute for a formal security audit by a
reputable third party.

## OPRF Protocol

The protocol relies on the following data types:
- `P`: A point on the curve derived from the input text using RFC 9497 HashToGroup.
- `r`: A random blinding factor chosen by the client to ensure that the blinded point `Q` is different for each submission, even for the same input.
- `Q`: The blinded point computed by the client as `Q = P · r`.
- `s`: A master secret key held by the service (skS).
- `R`: The blinded (ec point) result computed by the service as `R = Q · s = P · r · s`.
- `N`: The unblinded (ec point) result computed by the client as `N = r⁻¹ · R = s·P`.

The protocol flow is as follows:

```
Client                          Service
────────                        ───────
1. P = HashToGroup(input)
2. Q = P · r
3. Send Q  ─────────────────►   R = Q · s = P · r · s
           ◄─────────────────   R
4. N = R · r⁻¹ = P · s
5. identityKey = SHA-256(I2OSP(len(input),2) || input || I2OSP(33,2) || SerializeElement(N) || "Finalize")
```

> `I2OSP` — integer-to-octet-string primitive (RFC 8017 §4.1): encodes a non-negative integer
> as a fixed-length big-endian byte string.

### Details for each step

1. The client takes the input text (UTF-8 bytes) and applies RFC 9497 HashToGroup to derive a point `P` on the curve.
2. The client computes the blinded point `Q` by multiplying `P` with a random blinding factor `r`.
3. The client sends the blinded point `Q` to the service. The service computes `R` by multiplying `Q` with the master key `s`. This results in `R = s · P · r`.
4. The client receives `R` and unblinds it by multiplying with the inverse of the blinding factor `r`, yielding `N = s·P`.
5. Finally, the client derives a consistent identity key using the RFC 9497 Finalize function.

### Supported Cipher Suites (RFC 9497)

Three cipher suites are supported. P256-SHA256 is the default.

| Suite       | Curve | Hash    | contextString             |
|-------------|-------|---------|---------------------------|
| P256-SHA256 | P-256 | SHA-256 | `OPRFV1-\x00-P256-SHA256` |
| P384-SHA384 | P-384 | SHA-384 | `OPRFV1-\x00-P384-SHA384` |
| P521-SHA512 | P-521 | SHA-512 | `OPRFV1-\x00-P521-SHA512` |

#### P256-SHA256 detail

- **contextString**: `OPRFV1-\x00-P256-SHA256`
- **HashToGroup DST**: `HashToGroup-OPRFV1-\x00-P256-SHA256`
- **HashToScalar DST**: `HashToScalar-OPRFV1-\x00-P256-SHA256`
- **HashToGroup**: RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` (direct Simplified SWU, no isogeny)
- **Finalize**: `SHA-256(I2OSP(len(input),2) || input || I2OSP(33,2) || compressed_N || "Finalize")`
- **Key derivation**: RFC 9497 `DeriveKeyPair(seed, info)` using `HashToScalar` with counter

## OPAQUE Protocol

OPAQUE (RFC 9807) is an Augmented Password-Authenticated Key Exchange (aPAKE) protocol
built on top of OPRF. It enables password-based client authentication where the server
never sees the password, and a compromised server database does not expose the password
to offline dictionary attacks.

The protocol relies on the following data types:
- `pwd`: The client's password, never transmitted or stored in recoverable form.
- `skS`/`pkS`: The server's long-term static key pair.
- `skU`/`pkU`: The client's long-term key pair, derived deterministically during registration.
- `blind`: A random scalar blinding factor used in the OPRF sub-protocol (same role as `r` in OPRF).
- `oprfOutput`: The unblinded OPRF result; the root of all credential key material.
- `randomizedPwd`: A hardened key derived from `oprfOutput` via HKDF `Extract`.
- `maskingKey`: Derived from `randomizedPwd`; protects stored credentials during authentication.
- `envelope`: A server-stored record containing a random nonce and an HMAC authentication tag; contains no plaintext key material.
- `nonce`: A random value in the envelope; combined with `randomizedPwd` to deterministically re-derive `skU`.
- `Stretch`: The Key Stretching Function (KSF); currently Identity (no-op). The KSF interface is injectable; scrypt or Argon2 can be substituted.
- `sessionKey`: The shared symmetric secret established after successful mutual authentication.

OPAQUE has two phases: **Registration** (run once per user) and **Authentication** (run each login).

### Registration Flow

```
Client                                      Server
────────                                    ───────
pwd
1. blind, blindedMsg = Blind(pwd)
2. Send blindedMsg  ─────────────────────►  evaluatedMsg = Evaluate(skS, blindedMsg)
                    ◄─────────────────────  evaluatedMsg, pkS
3. oprfOutput = Finalize(pwd, blind, evaluatedMsg)
4. randomizedPwd = HKDF-Extract("", oprfOutput || Stretch(oprfOutput))
   nonce = Random(32)
   (skU, pkU) = DeriveAuthKeyPair(randomizedPwd, nonce)
5. authKey    = HKDF-Expand(randomizedPwd, nonce || "AuthKey",    Nh)
   maskingKey = HKDF-Expand(randomizedPwd, "MaskingKey",          Nh)
   authTag = HMAC(authKey, nonce || pkS || identities)
   envelope = nonce || authTag
6. Send (pkU, maskingKey, envelope) ──────► Store(credential_id → pkU, maskingKey, envelope)
```

#### Details for each step

1. **Blind**: The client blinds `pwd` via the OPRF sub-protocol (same mechanism as standalone OPRF), producing `blindedMsg`. The raw password never leaves the client.
2. **Evaluate**: The server evaluates `blindedMsg` with its OPRF secret key `skS`, returning `evaluatedMsg` and its long-term public key `pkS`.
3. **Finalize**: The client unblinds and hashes to produce `oprfOutput`. This value will be reproduced identically on every future login with the correct password.
4. **Key derivation**: `randomizedPwd` is derived by concatenating `oprfOutput` with `Stretch(oprfOutput)` (KSF) and applying `HKDF-Extract`. A fresh random `nonce` is generated, and the client's long-term key pair `(skU, pkU)` is derived
   deterministically — no private key is ever stored in plaintext.
5. **Envelope creation**: `authKey` and `maskingKey` are derived from `randomizedPwd`. An `authTag` authenticates `nonce`, `pkS`, and the parties' identities under `authKey`. The
   envelope is simply `nonce || authTag`.
6. **Upload**: The client sends `pkU`, `maskingKey`, and `envelope` to the server. The server stores this as the user's credential record. The server holds `maskingKey` but can learn
   nothing about `pwd` from it.

### Authentication Flow

```
Client                                      Server
────────                                    ───────
pwd
1. blind, blindedMsg = Blind(pwd)
   (eskU, epkU) = GenerateEphemeralKeyPair()
   nonceU = Random(32)
   KE1 = (blindedMsg, nonceU, epkU)
2. Send KE1  ────────────────────────────►  evaluatedMsg = Evaluate(skS, blindedMsg)
                                            (eskS, epkS) = GenerateEphemeralKeyPair()
                                            nonceS = Random(32)
                                            pad = HKDF-Expand(maskingKey, nonceS || "CredentialResponsePad", len(pkS) + len(envelope))
                                            maskedResponse = pad XOR (pkS || envelope)
                                            dh1=eskS·epkU, dh2=skS·epkU, dh3=eskS·pkU
                                            ikm=dh1||dh2||dh3; derive sessionKey, serverMAC
                                            KE2 = (evaluatedMsg, nonceS, epkS, maskedResponse, serverMAC)
              ◄──────────────────────────   KE2
3. oprfOutput = Finalize(pwd, blind, evaluatedMsg)
   randomizedPwd = HKDF-Extract("", oprfOutput || Stretch(oprfOutput))
   maskingKey = HKDF-Expand(randomizedPwd, "MaskingKey", Nh)
   pad = HKDF-Expand(maskingKey, nonceS || "CredentialResponsePad", ...)
   (pkS, envelope) = pad XOR maskedResponse
   (skU, pkU) = DeriveAuthKeyPair(randomizedPwd, nonce)  // nonce from envelope
   Verify serverMAC
4. dh1=eskU·epkS, dh2=eskU·pkS, dh3=skU·epkS
   ikm=dh1||dh2||dh3; derive sessionKey, clientMAC
   KE3 = clientMAC
5. Send KE3 ────────────────────────────►  Verify clientMAC
                                            ✓  Both parties hold sessionKey
```

#### Details for each step

1. **KE1**: The client blinds `pwd` and generates a fresh ephemeral key pair and random nonce. These form `KE1`.
2. **KE2**: The server evaluates the OPRF, generates its own ephemeral key pair and nonce, and uses `maskingKey` with `nonceS` to XOR-pad the stored `pkS || envelope`, hiding credential
   details from passive observers. It performs three DH operations; `eskS·epkU`, `skS·epkU`, `eskS·pkU`... concatenates them as ikm, then derives
   `sessionKey` and `serverMAC` from the full transcript.
3. **Credential recovery**: The client finalizes the OPRF, re-derives `randomizedPwd` (via KSF then `HKDF-Extract`) and `maskingKey`, unmasks the credential response to recover `pkS` and `envelope`, then re-derives
   `skU` from `randomizedPwd` and the nonce in the envelope. It then verifies `serverMAC` over the transcript, confirming the server holds the correct `skS`.
4. **KE3**: The client performs three DH operations; `eskU·epkS`, `eskU·pkS`, `skU·epkS`... concatenates them as ikm and derives the matching `sessionKey` and `clientMAC`, forming `KE3`.
5. **Mutual verification**: The client sends `KE3` to the server. The server verifies `clientMAC`. Both parties now hold the same authenticated `sessionKey`, completing the handshake.

### Cipher Suite: RFC 9807 OPAQUE-3DH (P-256)

- **OPRF**: RFC 9497 OPRF(P-256, SHA-256) mode 0 (same as above)
- **KDF**: HKDF-SHA-256
- **MAC**: HMAC-SHA-256
- **Hash**: SHA-256
- **KSF**: Identity (no additional key stretching; injectable — scrypt or Argon2 can be substituted)
- **AKE**: OPAQUE-3DH over P-256
- **Envelope mode**: Internal (client key pair is derived from `randomizedPwd` + `nonce`, not stored)

## References

### OPAQUE / aPAKE

OPAQUE is an Augmented Password-Authenticated Key Exchange (aPAKE) protocol that enables
clients to authenticate with a password without transmitting the password to the server.
A server compromise does not expose passwords to offline dictionary attacks because the
server never holds a recoverable form of the password.

- [Original Paper](https://eprint.iacr.org/2018/163.pdf)
- [Password-authenticated key exchange - Wikipedia](https://en.wikipedia.org/wiki/Password-authenticated_key_exchange)
- [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html)

### OPRF

Oblivious Pseudorandom Function (OPRF) is a cryptographic mechanism that allows
one party (the client) to compute a pseudorandom function on an input without
revealing the input to the other party (the server). The server holds a secret
key that is used to compute the pseudorandom function, but it does not learn
anything about the client's input. This is used for things like secure
multi-party computation.

- [Oblivious Pseudorandom Function - Wikipedia](https://en.wikipedia.org/wiki/Oblivious_pseudorandom_function)
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)

### Hash-to-Curve

Hash-to-curve is a technique used in elliptic curve cryptography to map arbitrary
input data (such as a string) to a point on an elliptic curve.
Protocols like OPRF use this technique to derive a point on the curve from the
input text. The hash-to-curve process ensures that the resulting point is
uniformly distributed on the curve. That uniform distribution is needed for
security applications.

Implements the [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html) specification,
validated against the RFC's own test vectors (Appendix J.7.1 for secp256k1,
Appendix A.1.1 for P-256, Appendix J.3.1 for P-384, and Appendix J.4.1 for P-521).

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
