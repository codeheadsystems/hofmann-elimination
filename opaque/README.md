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

| Constant | OPRF Suite | Hash | Public Key Size |
|---|---|---|---|
| `OpaqueCipherSuite.P256_SHA256` | P-256 / SHA-256 | SHA-256 | 33 bytes |
| `OpaqueCipherSuite.P384_SHA384` | P-384 / SHA-384 | SHA-384 | 49 bytes |
| `OpaqueCipherSuite.P521_SHA512` | P-521 / SHA-512 | SHA-512 | 67 bytes |

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

The server provides a fake KE2 for unregistered users that is computationally indistinguishable from a real response:

```java
ServerKE2Result fakeKe2 = server.generateFakeKE2(
    ke1, credentialIdentifier, serverIdentity, clientIdentity
);
```

The fake masking key and client public key are derived deterministically from the OPRF seed and credential identifier, ensuring consistent responses to the same input across server restarts.

## Key Classes

| Class | Role |
|---|---|
| `Client` | Public client API (stateless; state carried in `ClientRegistrationState` / `ClientAuthState`) |
| `Server` | Public server API (holds long-term key pair and OPRF seed) |
| `OpaqueConfig` | Protocol configuration (cipher suite, KSF, context) |
| `OpaqueCipherSuite` | Wrapper around `OprfCipherSuite` with OPAQUE-specific size constants |

### Internal Classes (not part of public API)

| Class | Role |
|---|---|
| `OpaqueOprf` | OPRF blind/evaluate/finalize operations and per-credential OPRF key derivation |
| `OpaqueCredentials` | Credential request/response lifecycle; credential masking/unmasking |
| `OpaqueEnvelope` | Envelope store (registration) and recover (authentication) |
| `OpaqueAke` | OPAQUE-3DH key exchange: preamble, 3DH, key derivation, MAC computation |
| `OpaqueCrypto` | Low-level primitives: HKDF, HMAC, ECDH, point (de)serialization, key derivation |

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

### Size Constants (P-256 example)

| Constant | Value | Meaning |
|---|---|---|
| `Npk` | 33 | Compressed public key / group element (bytes) |
| `Nsk` | 32 | Scalar / private key (bytes) |
| `Nh` | 32 | Hash output length (bytes) |
| `Nm` | 32 | MAC output length = Nh |
| `Nn` | 32 | Nonce length (suite-independent) |
| `envelopeSize()` | 64 | Nn + Nm |
| `maskedResponseSize()` | 97 | Npk + envelopeSize |

## Critical Implementation Details

### DH Output Format
`OpaqueCrypto.dhECDH()` returns a **33-byte compressed SEC1 point** via `result.getEncoded(true)`, not a 32-byte x-coordinate. This matches the RFC's definition of `SerializeElement`.

### MAC Computation
```
server_mac = HMAC(Km2, SHA256(preamble))
client_mac = HMAC(Km3, SHA256(preamble || server_mac))
```
The client MAC hashes the **concatenation** of preamble and server MAC — not their hashes separately.

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
- `hash-to-curve` — elliptic curve math (via oprf)
- BouncyCastle — EC arithmetic, HKDF, Argon2id

## Tests

| Test | Coverage |
|---|---|
| `OpaqueVectorsTest` | RFC 9807 test vectors (P-256 only, as specified in the RFC) |
| `OpaqueRoundTripTest` | Full registration + auth parameterized over all cipher suites; correct/wrong password cases; with/without explicit identities |

Test vectors from [RFC 9807 Appendix C](https://www.rfc-editor.org/rfc/rfc9807.html#appendix-C).
