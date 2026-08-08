# opaque — RFC 9807 OPAQUE aPAKE Protocol

This module implements [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html) OPAQUE-3DH: an Augmented Password-Authenticated Key Exchange (aPAKE) protocol. It depends on the `oprf` module (RFC 9497) and `hash-to-curve` (RFC 9380).

## What It Provides

OPAQUE enables password-based authentication where:
- The password is **never transmitted** to the server
- The server stores no recoverable form of the password
- A compromised server database does **not** expose passwords to offline dictionary attacks
- Successful authentication establishes a mutual, authenticated session key

## Cipher Suites

`OpaqueCipherSuite` wraps `OprfCipherSuite` and adds OPAQUE-specific size constants (`Npk`, `Nsk`, `Nh`, `Nm`, `Nn`):

| Constant | OPRF Suite | Hash | Npk | Nsk | Nh |
|---|---|---|---|---|---|
| `OpaqueCipherSuite.P256_SHA256` | P-256 / SHA-256 | SHA-256 | 33 | 32 | 32 |
| `OpaqueCipherSuite.P384_SHA384` | P-384 / SHA-384 | SHA-384 | 49 | 48 | 48 |
| `OpaqueCipherSuite.P521_SHA512` | P-521 / SHA-512 | SHA-512 | 67 | 66 | 64 |
| `OpaqueCipherSuite.RISTRETTO255_SHA512` | ristretto255 / SHA-512 | SHA-512 | 32 | 32 | 64 |

Note that for ristretto255, `Npk == Nsk == 32` because both group elements and scalars are 32-byte little-endian encodings. For Weierstrass curves, `Npk > Nsk` because public keys are compressed SEC1 points (with a 1-byte prefix).

## Configuration

`OpaqueConfig` is a record that holds the cipher suite, KSF parameters, and application context:

```java
// Default (Argon2id, P-256, context="OPAQUE-3DH")
OpaqueConfig config = OpaqueConfig.DEFAULT;

// Custom Argon2id parameters
OpaqueConfig config = OpaqueConfig.withArgon2id(
    "MyApp".getBytes(), // context
    65536,              // memory (KB)
    3,                  // iterations
    1                   // parallelism
);

// For test vectors (identity KSF, no key stretching)
OpaqueConfig config = OpaqueConfig.forTesting();
OpaqueConfig config = OpaqueConfig.forTesting(OpaqueCipherSuite.P384_SHA384);
```

Key Stretching Functions (KSF):
- `Argon2idKsf` — BouncyCastle Argon2id with a zero-byte salt; used by default
- `IdentityKsf` — no-op; used for RFC test vectors

## Public API

### Registration Flow

Run once per user. The client derives and uploads its credential record without ever sending the password.

```
Client                                          Server
────────                                        ───────
1. (blind, blindedMsg) = Blind(pwd)
2. Send RegistrationRequest ─────────────────►  evaluatedMsg = Evaluate(oprfKey, blindedMsg)
                             ◄─────────────────  RegistrationResponse(evaluatedMsg, pkS)
3. oprfOutput = Finalize(pwd, blind, evaluatedMsg)
   randomizedPwd = HKDF-Extract("", oprfOutput || Stretch(oprfOutput))
   nonce = Random(32)
   skU/pkU derived deterministically from randomizedPwd + nonce
   envelope = nonce || HMAC(authKey, nonce || pkS || identities)
4. Send RegistrationRecord(pkU, maskingKey, envelope) ──► Store(credentialId → record)
```

```java
// Client side
Client client = new Client(config);
ClientRegistrationState state = client.createRegistrationRequest(password);
RegistrationRequest request = state.request();

// Server side
Server server = Server.generate(config); // generates server key pair + OPRF seed
RegistrationResponse response = server.createRegistrationResponse(request, credentialIdentifier);

// Client side — finalize
RegistrationRecord record = client.finalizeRegistration(
    state, response,
    serverIdentity,   // null defaults to server public key
    clientIdentity    // null defaults to client public key
);
// → record is stored on the server, keyed by credentialIdentifier
```

### Authentication Flow

Three-message mutual authentication establishing a shared session key.

```
Client                                          Server
────────                                        ───────
1. (blind, blindedMsg) = Blind(pwd)
   (eskU, epkU) = GenerateEphemeralKeyPair()
   KE1 = (blindedMsg, nonceU, epkU)
2. Send KE1 ─────────────────────────────────►  evaluatedMsg = Evaluate(oprfKey, blindedMsg)
                                                 (eskS, epkS) = GenerateEphemeralKeyPair()
                                                 maskedResponse = maskingKey-pad XOR (pkS || envelope)
                                                 dh1=eskS·epkU, dh2=skS·epkU, dh3=eskS·pkU
                                                 ikm = dh1 || dh2 || dh3
                                                 derive sessionKey, serverMAC
                                                 KE2 = (evaluatedMsg, nonceS, epkS, maskedResponse, serverMAC)
             ◄────────────────────────────────  KE2
3. Recover randomizedPwd, unmask pkS || envelope
   Re-derive skU from randomizedPwd + envelopeNonce
   Verify serverMAC; compute clientMAC
   KE3 = clientMAC
4. Send KE3 ─────────────────────────────────►  Verify clientMAC
                                                 ✓ Both parties hold sessionKey
```

```java
// Client
Client client = new Client(config);
ClientAuthState ke1State = client.generateKE1(password);
KE1 ke1 = ke1State.ke1();

// Server (returns state needed to verify KE3, plus KE2 to send back)
ServerKE2Result ke2Result = server.generateKE2(
    serverIdentity, record, credentialIdentifier, ke1, clientIdentity
);
KE2 ke2 = ke2Result.ke2();

// Client (verifies server MAC, produces KE3)
AuthResult authResult = client.generateKE3(ke1State, clientIdentity, serverIdentity, ke2);
KE3 ke3 = authResult.ke3();
byte[] sessionKey = authResult.sessionKey();
byte[] exportKey  = authResult.exportKey();  // application-specific secret

// Server (verifies client MAC, returns session key)
byte[] serverSessionKey = server.serverFinish(ke2Result.serverAuthState(), ke3);
// sessionKey.equals(serverSessionKey) → true
```

### User Enumeration Protection

Answer both cases through one call, passing `null` for the record when the credential is not registered:

```java
// record == null → a fake KE2, and the same work either way
ServerKE2Result ke2 = server.generateKE2ForRecordOrFake(
    serverIdentity, record, credentialIdentifier, ke1, clientIdentity
);
```

The fake masking key and client public key are derived deterministically from the OPRF seed and credential identifier, so the same input gets the same response across server restarts.

**Do not call `generateFakeKE2` on only the unregistered branch.** That is what this guide used to show, and it reproduces a user-enumeration oracle: building the fake record costs two HKDF expansions and a full `deriveAkeKeyPair` — a hash-to-scalar loop and a generator scalar multiplication — that the registered branch does not pay. Measured at a 17–20% one-directional offset, distinguishable in roughly 200 probes per identifier. RFC 9807 §10.6 asks for a response that does not reveal whether the account exists; a response body that is indistinguishable does not help when the latency is not. `generateKE2ForRecordOrFake` builds the fake record unconditionally and discards it when unused, so both branches pay. `generateFakeKE2` is deprecated and remains only for callers that already depend on it.

**Two things this does not cover, and one of them dominates in production.**

- **The credential store lookup.** A hit and a miss are indistinguishable against the in-memory store, but on the JDBC- or Redis-backed `CredentialStore` recommended for production they are not — and that signal is larger and more reliable than the one above. Equalising the protocol work does not help when the lookup in front of it is not equal.

  **If you use `HofmannOpaqueServerManager`, this is covered up to a point that is worth knowing.** `authStart` runs the lookup and everything after it under a 25 ms constant-time floor, so the store's answer time is absorbed without the store having to be constant-time itself. Earlier versions of this note said the fix belonged in the store; it does not, and requiring every `CredentialStore` implementor to build a constant-time database lookup would have been a contract almost none could meet.

  The point: **the floor stops working before its nominal 25 ms** — `authStart`'s own work is roughly 2 ms and is spent inside the floor too. Measured, a store gap up to 15 ms is absorbed; a 20 ms gap leaks a little; and past roughly 22–23 ms the oracle returns in full. An overloaded database or a cross-region Redis needs the constant raised.

  Those figures were taken on an ordinary shared development machine rather than a host prepared for timing work, and noise pulls this kind of measurement toward "no signal" — so treat "absorbed" as *not detected here*, and re-measure on your own hardware if the answer matters to you.

  **If you have built your own endpoint on `Server` directly, the floor is yours to add.** Take the deadline before the lookup and sleep to it in a `finally`. Three things that are easy to get wrong, all of which this repo got wrong first and fixed:

  - **Cap how many requests may be inside the floor at once.** A floor that parks a request thread is a thread-exhaustion vector; without a ceiling a few hundred connections take down the whole application rather than one endpoint. Refuse rather than queue.
  - **Check that ceiling before you charge a rate-limit token.** Otherwise a flood that fills the ceiling spends the tokens of the users it refuses, and locks them out past the end of the flood.
  - **End the wait with a settling phase of fixed shape**, not with one long sleep — and not with uniform slices either. `Thread.sleep` does not exit exactly on time, and how late it exits depends on the sleep's length *and* on what the thread was doing beforehand; a floor sleeps for whatever the branch left over, so that carries the branch through the floor. Uniform 1 ms slices look like the fix and measured **worse than doing nothing** (AUC 0.48–0.74 with a stable direction, against 0.34–0.53 unstable for one long sleep): the final slice is the same size on both branches but the *number* of slices is not, and a thread that has just taken 23 consecutive timer wakeups is in a different state from one that took 13. What works is one coarse sleep followed by small steps of fixed size — AUC 0.42–0.55, better than a single sleep at every store gap from 1 to 21 ms.

    **And know where that stops holding.** The shape is only identical while the branch has more time left than the settling window. Once a branch arrives with less than that, the coarse sleep is skipped and the step count goes branch-dependent again — structural, not statistical, and visible by reading the loop. Measured at AUC 0.82–0.84 at a 22 ms store gap under a 25 ms floor. Size the floor so that neither branch lands in that band, rather than relying on the settling phase to save you there.

  A general warning about all the numbers in this section: they come from an ordinary development machine, and measurements like these move by an order of magnitude between runs on one. Interleave the arms sample by sample — that is what makes a comparison survive it — and trust orderings well ahead of magnitudes.
- **Anything else you do on one branch only.** A single per-request log statement on the unregistered path measured 31.2 µs against an ordinary logback configuration, which is a *cheaper* oracle than the one this API closes. That particular one is now inside the manager's floor, but "the floor will cover it" is not a licence: nothing notices when a branch grows past 25 ms. If you must log a branch-specific condition, log it once per condition rather than once per request.

## Key Classes

| Class | Role |
|---|---|
| `Client` | Public client API (stateless; state carried in `ClientRegistrationState` / `ClientAuthState`) |
| `Server` | Public server API (holds long-term key pair and OPRF seed) |
| `OpaqueConfig` | Protocol configuration (cipher suite, KSF, context) |
| `OpaqueCipherSuite` | Wrapper around `OprfCipherSuite`: size constants (`Npk`, `Nsk`, `Nh`, `Nm`, `Nn`) and the low-level primitives `hkdfExtract`, `hkdfExpand`, `hkdfExpandLabel`, `hmac`, `hash`, `deriveAkeKeyPair` |

### Internal Classes (not reachable from outside the package)

All four are package-private and `final`, in `com.codeheadsystems.rfc.opaque` alongside `Client` and `Server`.

| Class | Role |
|---|---|
| `OpaqueOprf` | OPRF blind/evaluate/finalize operations and per-credential OPRF key derivation |
| `OpaqueCredentials` | Credential request/response lifecycle; credential masking/unmasking |
| `OpaqueEnvelope` | Envelope store (registration) and recover (authentication) |
| `OpaqueAke` | OPAQUE-3DH key exchange: preamble, 3DH (via `GroupSpec.scalarMultiply`), key derivation, MAC computation |

They used to be public, in a `...opaque.internal` sub-package. That arrangement documented an
intent it did not enforce: every capability deliberately kept off `Client` and `Server` — a
caller-supplied blind, envelope nonce, masking nonce and server AKE seed — was public one package
over, and a reviewer rebuilt all of them, replay included, from another package using public API
and no reflection. Folding the package in is what makes those methods actually unreachable, and it
is why there is no bridge class to keep in step with anything.

Two things hold the boundary in place, because a comment does not:

- **`PackageBoundaryTest`** enumerates every class compiled into `com.codeheadsystems.rfc.opaque`
  and pins the full public surface *by signature*. Signatures rather than names on purpose:
  `OpaqueAke.generateKE2` took the masking nonce and the server AKE seed as ordinary parameters,
  so the older name-based check could not have seen it however carefully it was written.
- **Jar sealing.** Package-private is a compile-time rule keyed on the package *name*, so a class
  declared into `com.codeheadsystems.rfc.opaque` from another jar compiles against these methods
  and calls them. The published jar seals `com/codeheadsystems/rfc/opaque/`, and a sealed package
  must come from one code source, so that class fails to load — verified both ways, and asserted
  on the artifact by `:hofmann-rfc:verifyOpaquePackageSealed`.

Sealing rather than a `module-info.java`, which was the other candidate: a `module-info` takes
effect only on the module path, and this library is consumed from the class path, where it is
inert. Sealing applies in both.

**What remains reachable, inherently.** None of this makes the *behaviours* unreachable, and it was
never the claim — the claim is about what a caller reaches by accident.

- **The injectable random source reaches all of them at once.** `OprfCipherSuite.Builder.withRandom`
  and `OpaqueConfig.withRandomConfig` are production API — `withRandom` is how an operator installs
  an HSM-backed or policy-constrained source — and every nonce and seed in the protocol is drawn
  through them. A `SecureRandom` subclass whose `nextBytes` writes a constant fixes the blind, the
  envelope nonce, the masking nonce, the server AKE seed and the server nonce together, from any
  package, with no reflection; a reviewer replayed a full authentication that way, and recovered a
  server's long-term key from a rigged suite RNG. This is an accepted residual whose reasoning lives
  on `OprfCipherSuite.withRandom`: nothing can tell a hardware source from a fixed-output stub, and
  a caller who supplies a broken one has broken any crypto library, not this one.
- **A fixed-blind KE1 can be assembled by hand**, since `ClientAuthState`'s canonical constructor is
  public (the record is returned from `generateKE1`) and `blind · H(password)` is computable from
  `GroupSpec`, published deliberately as the RFC 9497 implementation. That is reimplementing the
  client from primitives.

The difference that justifies the change is accident surface, not reachability. Passing a constant
to a parameter that asks for one is what pasting an RFC test vector into production code looks like.
Writing a `SecureRandom` that ignores its output buffer is not something anyone does by mistake.

## Wire Format

### Message Records

| Record | Wire Layout |
|---|---|
| `RegistrationRequest` | `blindedElement` (Noe bytes) |
| `RegistrationResponse` | `evaluatedElement` (Noe) \|\| `serverPublicKey` (Npk) |
| `RegistrationRecord` | stored server-side: `clientPublicKey` (Npk) \|\| `maskingKey` (Nh) \|\| `envelope` |
| `Envelope` | `envelopeNonce` (32) \|\| `authTag` (Nh) |
| `KE1` | `blindedElement` (Noe) \|\| `clientNonce` (32) \|\| `clientAkePublicKey` (Npk) |
| `KE2` | `credentialResponse` \|\| `serverNonce` (32) \|\| `serverAkePublicKey` (Npk) \|\| `serverMac` (Nm) |
| `KE3` | `clientMac` (Nm) |

Where `Noe = Npk` (element and public key have the same size per curve).

`KE2.deserialize()` requires `OpaqueConfig` because element sizes vary by cipher suite.

### Size Constants

| Constant | P-256 | P-384 | P-521 | ristretto255 | Meaning |
|---|---|---|---|---|---|
| `Npk` | 33 | 49 | 67 | 32 | Public key / group element (bytes) |
| `Nsk` | 32 | 48 | 66 | 32 | Scalar / private key (bytes) |
| `Nh` | 32 | 48 | 64 | 64 | Hash output length (bytes) |
| `Nm` | 32 | 48 | 64 | 64 | MAC output length = Nh |
| `Nn` | 32 | 32 | 32 | 32 | Nonce length (suite-independent) |
| `envelopeSize()` | 64 | 80 | 96 | 96 | Nn + Nm |
| `maskedResponseSize()` | 97 | 129 | 163 | 128 | Npk + envelopeSize |

## Critical Implementation Details

### DH Output Format
`OpaqueAke` performs Diffie-Hellman via `GroupSpec.scalarMultiply()`, which returns a serialized group element. The output format depends on the suite:
- **Weierstrass curves**: compressed SEC1 point (33/49/67 bytes) — not a raw x-coordinate
- **ristretto255**: canonical ristretto255 encoding (32 bytes)

This abstraction allows `OpaqueAke` to work with any `GroupSpec` without knowledge of the underlying curve type. The earlier coupling to BouncyCastle `ECPoint` has been removed.

### MAC Computation
```
server_mac = HMAC(Km2, Hash(preamble))
client_mac = HMAC(Km3, Hash(preamble || server_mac))
```
Where `Hash` is the suite's hash function (SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521 and ristretto255). The client MAC hashes the **concatenation** of preamble and server MAC — not their hashes separately.

### Constant-Time Comparisons
MAC verification (`serverFinish` and AKE internally) uses `MessageDigest.isEqual()` to prevent timing-based oracle attacks.

## Deterministic APIs

For test vector validation, both `Client` and `Server` expose deterministic variants where random values (blind, nonce, seed) are caller-supplied:

```java
client.createRegistrationRequestDeterministic(password, blind);
client.finalizeRegistrationDeterministic(state, response, serverIdentity, clientIdentity, envelopeNonce);
client.generateKE1Deterministic(password, blind, clientNonce, clientAkeKeySeed);

server.generateKE2Deterministic(..., maskingNonce, serverAkeKeySeed, serverNonce);
server.generateFakeKE2Deterministic(..., fakeClientPublicKey, fakeMaskingKey, ...);
```

## Dependencies

- `oprf` — `OprfCipherSuite`, blinding, OPRF evaluation
- `hash-to-curve` — `GroupSpec` interface, elliptic curve math (via oprf)
- BouncyCastle — HKDF, Argon2id, EC arithmetic for Weierstrass curves (ristretto255 uses pure `BigInteger` arithmetic)

## Tests

| Test | Coverage |
|---|---|
| `OpaqueVectorsTest` | RFC 9807 test vectors (P-256 only, as specified in the RFC) |
| `OpaqueRoundTripTest` | Full registration + auth parameterized over all four cipher suites (P-256, P-384, P-521, ristretto255); correct/wrong password cases; with/without explicit identities |

Test vectors from [RFC 9807 Appendix C](https://www.rfc-editor.org/rfc/rfc9807.html#appendix-C).
