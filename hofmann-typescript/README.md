# hofmann-typescript

Browser/Node TypeScript client for the [Hofmann Elimination](../README.md) OPRF and OPAQUE server.

Implements:
- **RFC 9497** — Oblivious Pseudorandom Functions (OPRF)
- **RFC 9807** — OPAQUE-3DH password-authenticated key exchange

Supported cipher suites:

| Suite | Curve | Hash | Nh | Npk |
|---|---|---|---|---|
| `P256_SHA256` | P-256 | SHA-256 | 32 bytes | 33 bytes |
| `P384_SHA384` | P-384 | SHA-384 | 48 bytes | 49 bytes |
| `P521_SHA512` | P-521 | SHA-512 | 64 bytes | 67 bytes |

The active suite is negotiated automatically from the server's `/opaque/config` endpoint — no hardcoding required.

All cryptography is built on [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes). No native bindings, no WebAssembly (except the optional Argon2id KSF via `hash-wasm`).

> **Security notice:** This implementation has not undergone a formal security audit. See the [parent project](../README.md) for full details.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Cipher Suites](#cipher-suites)
- [Configuration](#configuration)
- [API Reference](#api-reference)
  - [OpaqueHttpClient](#opaquehttpclient)
  - [OprfHttpClient](#oprfhttpclient)
  - [OpaqueClient (low-level)](#opaqueclient-low-level)
  - [Key Stretching Functions (KSF)](#key-stretching-functions-ksf)
- [Interactive Demo](#interactive-demo)
- [Running Tests](#running-tests)
- [Building](#building)
- [Project Structure](#project-structure)

---

## Installation

```bash
npm install hofmann-typescript
```

Dependencies pulled in automatically:

| Package | Purpose |
|---|---|
| `@noble/curves` | P-256, P-384, P-521 elliptic curve arithmetic and hash-to-curve |
| `@noble/hashes` | SHA-256, SHA-384, SHA-512, HMAC, HKDF |
| `hash-wasm` | Argon2id key stretching (only loaded when used) |

---

## Quick Start

### OPAQUE registration and login

The recommended way to create a client is via `OpaqueHttpClient.create()`. It fetches the server's `/opaque/config` endpoint and automatically configures the cipher suite, protocol context, and Argon2id parameters — no manual configuration needed:

```typescript
import { OpaqueHttpClient } from 'hofmann-typescript';

// Fetches /opaque/config → resolves cipher suite (P-256/P-384/P-521),
// context string, and Argon2id parameters automatically.
const client = await OpaqueHttpClient.create('https://your-server.example.com');

// Register a new user (run once)
await client.register('alice@example.com', 'hunter2');

// Authenticate (every login) — returns a JWT bearer token
const token = await client.authenticate('alice@example.com', 'hunter2');
console.log('JWT:', token);

// Delete a registration (requires a valid token)
await client.deleteRegistration('alice@example.com', token);
```

### Standalone OPRF evaluation

```typescript
import { OprfHttpClient } from 'hofmann-typescript';
import { strToBytes } from 'hofmann-typescript';

// Fetches /oprf/config → resolves cipher suite automatically.
const client = await OprfHttpClient.create('https://your-server.example.com');
const result = await client.evaluate(strToBytes('my-secret-input'));
// result is a stable Nh-byte Uint8Array — same every time for the same input and server key
// Nh = 32 (P-256), 48 (P-384), or 64 (P-521) depending on server configuration
```

---

## Cipher Suites

A `CipherSuite` encapsulates all curve-specific operations (hash-to-curve, scalar arithmetic, hash/MAC/HKDF with the appropriate hash function) and the RFC 9497 domain-separation strings.

```typescript
import { P256_SHA256, P384_SHA384, P521_SHA512, getCipherSuite } from 'hofmann-typescript';
import type { CipherSuite } from 'hofmann-typescript';
```

### Named suite constants

| Export | Curve | Hash | Nh | Npk | Nsk | L |
|---|---|---|---|---|---|---|
| `P256_SHA256` | P-256 | SHA-256 | 32 | 33 | 32 | 48 |
| `P384_SHA384` | P-384 | SHA-384 | 48 | 49 | 48 | 72 |
| `P521_SHA512` | P-521 | SHA-512 | 64 | 67 | 66 | 98 |

*Nh = hash output length · Npk = compressed public key size · Nsk = scalar size · L = hashToScalar expand length*

### `getCipherSuite(name): CipherSuite`

Resolves a suite by the name string returned in server config responses:

```typescript
import { getCipherSuite } from 'hofmann-typescript';

const suite = getCipherSuite('P384_SHA384'); // returns P384_SHA384
```

Accepted values: `"P256_SHA256"`, `"P384_SHA384"`, `"P521_SHA512"`. Throws for any other value.

### Using a suite directly

```typescript
const suite = P384_SHA384;

// Blind an input
const { blind, blindedElement } = suite.blind(inputBytes);

// Finalize after server evaluation (returns Nh=48 bytes for P-384)
const output = suite.finalize(inputBytes, blind, evaluatedElement);

// Hash/MAC/HKDF using the suite's hash function (SHA-384 for P-384)
const hash   = suite.hash(data);
const mac    = suite.hmac(key, data);
const prk    = suite.hkdfExtract(undefined, ikm);
const keyMat = suite.hkdfExpand(prk, info, 48);
```

---

## Configuration

### Auto-configuration (recommended)

`OpaqueHttpClient.create()` and `OprfHttpClient.create()` call the server's config endpoint and set everything automatically. Use these factories in production and in the integration tests.

```typescript
const client = await OpaqueHttpClient.create('https://your-server.example.com');
console.log(client.configResponse);
// {
//   cipherSuite:      "P384_SHA384",
//   context:          "my-app",
//   argon2MemoryKib:  65536,
//   argon2Iterations: 3,
//   argon2Parallelism: 1
// }
```

### Manual configuration

If you need to construct the client manually (e.g., to pin a specific cipher suite or supply a custom KSF):

```typescript
import { OpaqueHttpClient, P384_SHA384, argon2idKsf } from 'hofmann-typescript';

const client = new OpaqueHttpClient('http://localhost:8080', {
  suite:   P384_SHA384,
  context: 'my-app',
  ksf:     argon2idKsf(65536, 3, 1),
});
```

The `context` string and Argon2id parameters **must exactly match the server's configuration**. A mismatch causes silent authentication failure that is indistinguishable from a wrong password.

For a Dropwizard server, look at the YAML configuration:

```yaml
# hofmann-testserver/config/config.yml (example)
cipherSuite: P384_SHA384
context: hofmann-testserver
argon2MemoryKib: 65536
argon2Iterations: 3
argon2Parallelism: 1
```

### Identity KSF (test servers only)

If the server has `argon2MemoryKib: 0` (identity KSF, no Argon2), the `create()` factory handles this automatically. When constructing manually, omit `ksf` or pass `identityKsf`:

```typescript
import { OpaqueHttpClient, identityKsf } from 'hofmann-typescript';

const client = new OpaqueHttpClient('http://localhost:8080', {
  context: 'my-test-context',
  // ksf defaults to identityKsf when omitted
});
```

> **Do not use identity KSF against a production server.** It disables password hardening.

---

## API Reference

### OpaqueHttpClient

The main entry point. Handles the full OPAQUE-3DH protocol over HTTP.

#### `OpaqueHttpClient.create(baseUrl): Promise<OpaqueHttpClient>` *(recommended)*

Fetches `GET /opaque/config`, resolves the cipher suite and KSF automatically, and returns a configured client.

```typescript
const client = await OpaqueHttpClient.create('https://your-server.example.com');
// client.configResponse holds the raw server response
```

#### `new OpaqueHttpClient(baseUrl, options?)`

Manual constructor. All options default to P-256/SHA-256 with identity KSF when omitted.

**`OpaqueHttpClientOptions`**

| Field | Type | Default | Description |
|---|---|---|---|
| `suite` | `CipherSuite` | `P256_SHA256` | Cipher suite. Must match the server's configured suite. |
| `context` | `string` | `""` | OPAQUE protocol context. Must match `context` in server config. |
| `ksf` | `KSF` | `identityKsf` | Key stretching function. Use `argon2idKsf(...)` for production. |

#### `register(credentialId, password, serverIdentity?, clientIdentity?): Promise<void>`

Runs the three-message OPAQUE registration flow:
1. Sends `blindedElement` to `POST /opaque/registration/start`
2. Receives `evaluatedElement` and `serverPublicKey`
3. Derives the envelope locally using the KSF
4. Uploads `clientPublicKey`, `maskingKey`, and `envelope` to `POST /opaque/registration/finish`

The password never leaves the client in plaintext.

```typescript
await client.register('alice@example.com', 's3cr3t');

// With explicit identities (advanced — must match the server's identity config)
await client.register('alice@example.com', 's3cr3t', 'server.example.com', 'alice@example.com');
```

#### `authenticate(credentialId, password, serverIdentity?, clientIdentity?): Promise<string>`

Runs the three-message OPAQUE-3DH authentication flow (KE1 → KE2 → KE3):
1. Generates KE1 (blind password, generate ephemeral AKE key pair)
2. Sends to `POST /opaque/auth/start`, receives KE2
3. Verifies the server MAC — **throws if wrong password or server mismatch**
4. Sends KE3 (client MAC) to `POST /opaque/auth/finish`
5. Returns the JWT bearer token from the server

```typescript
const token = await client.authenticate('alice@example.com', 's3cr3t');
// Use token in subsequent requests:
// Authorization: Bearer <token>
```

Throws an `Error` if the password is incorrect, the server MAC fails, or a network/HTTP error occurs.

#### `deleteRegistration(credentialId, token): Promise<void>`

Sends `DELETE /opaque/registration` with the `Authorization: Bearer <token>` header.

```typescript
await client.deleteRegistration('alice@example.com', token);
```

---

### OprfHttpClient

Standalone OPRF client for the `/oprf` endpoint. Useful when you want a server-keyed pseudorandom function without the full OPAQUE flow.

#### `OprfHttpClient.create(baseUrl): Promise<OprfHttpClient>` *(recommended)*

Fetches `GET /oprf/config`, resolves the cipher suite, and returns a configured client.

```typescript
const client = await OprfHttpClient.create('https://your-server.example.com');
// client.cachedConfig.cipherSuite tells you which suite the server uses
```

#### `new OprfHttpClient(baseUrl, suite?)`

Manual constructor. Defaults to `P256_SHA256` when `suite` is omitted.

#### `evaluate(input: Uint8Array): Promise<Uint8Array>`

Returns a stable `Nh`-byte value. The same input always produces the same output for a given server key. The server learns nothing about `input` — it sees only the blinded EC point.

Output length matches the suite: 32 bytes (P-256), 48 bytes (P-384), or 64 bytes (P-521).

```typescript
const client = await OprfHttpClient.create('https://your-server.example.com');
const output = await client.evaluate(strToBytes('my-input'));
console.log(output.length); // 32, 48, or 64 depending on server suite
```

---

### OpaqueClient (low-level)

The `OpaqueClient` class implements OPAQUE cryptographic operations without any HTTP transport. Pass a `CipherSuite` to the constructor to select the suite; defaults to `P256_SHA256`.

```typescript
import { OpaqueClient, P384_SHA384, identityKsf, argon2idKsf } from 'hofmann-typescript';
import type { KSF, CipherSuite } from 'hofmann-typescript';

const suite: CipherSuite = P384_SHA384;
const client = new OpaqueClient(suite);
const ksf: KSF = argon2idKsf(65536, 3, 1);

// ── Registration ────────────────────────────────────────────────────────────

// Step 1a: create registration request
const regState = client.createRegistrationRequest(passwordBytes);
// regState.blindedElement (Npk bytes) → send to server

// Step 1c: finalize registration (after receiving server response)
const record = await client.finalizeRegistration(
  regState,
  { evaluatedElement, serverPublicKey },  // from server
  null,         // serverIdentity (null = use serverPublicKey)
  null,         // clientIdentity (null = use derived clientPublicKey)
  undefined,    // envelopeNonce (undefined = random)
  ksf           // key stretching function
);
// record.clientPublicKey (Npk bytes), record.maskingKey (Nh bytes),
// record.envelope.nonce (32 bytes), record.envelope.authTag (Nh bytes) → upload to server

// ── Authentication ──────────────────────────────────────────────────────────

// Step 2a: generate KE1
const { state, ke1Bytes } = client.generateKE1(passwordBytes);
// ke1Bytes = blindedElement (Npk) || clientNonce (32) || clientAkePk (Npk) → send to server

// Step 2c: generate KE3 after receiving KE2 from server
const authResult = await client.generateKE3(
  state,
  ke2,          // KE2 object with evaluatedElement, maskingNonce, maskedResponse, etc.
  null,         // clientIdentity
  null,         // serverIdentity
  contextBytes, // application context (must match server)
  ksf           // key stretching function
);
// authResult.clientMac (Nh bytes) → send to server as KE3
// authResult.sessionKey (Nh bytes) → shared session key
// authResult.exportKey  (Nh bytes) → optional export key for application use
```

Key sizes scale with the suite's `Nh` and `Npk` — for P-256 these are 32 and 33 bytes respectively; for P-384, 48 and 49; for P-521, 64 and 67.

**Deterministic variants for testing:**

```typescript
// Fixed blind scalar — produces identical blinded elements for RFC test vectors
const regState = client.createRegistrationRequestDeterministic(password, blindScalar);

// Fixed nonces and AKE seed — produces identical KE1 for RFC test vectors
const { state } = client.generateKE1Deterministic(
  password, blindScalar, clientNonce, clientAkeSeed
);
```

---

### Key Stretching Functions (KSF)

The KSF is applied to the raw OPRF output before HKDF derives `randomizedPwd`. The client and server must use the same KSF and parameters at all times — changing them after registration invalidates all existing credentials.

```typescript
import { identityKsf, argon2idKsf, type KSF } from 'hofmann-typescript';
```

#### `identityKsf`

No stretching — the OPRF output is used directly. Appropriate only for testing with servers configured with `argon2MemoryKib: 0`. This is the default when `ksf` is omitted from `OpaqueHttpClientOptions`.

#### `argon2idKsf(memoryKib, iterations, parallelism): KSF`

Returns an Argon2id key stretching function with a 32-byte all-zero salt and 32-byte output, matching the server's implementation.

```typescript
// Matching hofmann-testserver defaults
const ksf = argon2idKsf(65536, 3, 1);
```

`hash-wasm` is loaded on demand the first time `argon2idKsf` is invoked; there is no startup cost if identity KSF is used.

#### Custom KSF

The `KSF` type is `(input: Uint8Array) => Promise<Uint8Array>`. Any async function works:

```typescript
const myKsf: KSF = async (input) => {
  return stretchedOutput; // custom key stretching
};
```

---

## Interactive Demo

A browser-based demo page is included for manual testing against a running server.

```bash
npm run demo
```

This starts a Vite dev server at `http://localhost:5173/demo.html` and proxies `/opaque` and `/oprf` requests to `http://localhost:8080`, avoiding CORS issues.

On page load the demo automatically calls `GET /opaque/config` and populates the **Server Configuration** panel with the cipher suite, context, and Argon2id parameters from the server. Every subsequent operation re-fetches the config so it is always in sync with the server.

To target a different server:

```bash
HOFMANN_SERVER=http://other-server:8080 npm run demo
```

The demo provides:
- **Server Configuration** — displays cipher suite, context, and Argon2id params loaded from the server (↺ Load Config button refreshes manually)
- **OPAQUE Registration** — enter credential ID and password, click Register
- **OPAQUE Authentication** — returns a JWT token (auto-fills the Delete form)
- **Delete Registration** — removes the credential (requires the JWT from authentication)
- **Standalone OPRF** — evaluate an arbitrary plaintext; output length shown dynamically
- **Activity log** — timestamped protocol step log

---

## Running Tests

### RFC vector tests and round-trip tests (no server required)

```bash
npm test
```

Runs 34 tests:

- **`test/oprf.test.ts`** — RFC 9497 P-256/SHA-256 vectors (DSTs, `blind`, `finalize`, `deriveKeyPair`); P-384 and P-521 constant and DST verification; `getCipherSuite()` lookup; per-suite OPRF round-trip consistency checks for all three suites
- **`test/opaque.test.ts`** — RFC 9807 OPAQUE-3DH vectors against P-256/SHA-256 CFRG test vectors (registration records, KE1 bytes, server MAC, full AKE); multi-suite round-trip tests for P-256, P-384, and P-521

### Integration tests (requires running server)

```bash
TEST_SERVER_URL=http://localhost:8080 npm test -- integration
```

Uses `OpaqueHttpClient.create()` and `OprfHttpClient.create()` so the cipher suite and Argon2id parameters are read from the server — no hardcoded values. Runs:
- Cipher suite and Argon2id config verification (asserts `configResponse` fields)
- Full register → authenticate → wrong-password-rejection → delete flow

Each OPAQUE operation has a 30-second timeout to accommodate Argon2id processing time. Tests are skipped automatically when `TEST_SERVER_URL` is not set.

### Watch mode

```bash
npm run test:watch
```

---

## Building

```bash
npm run build
```

Produces two bundles in `dist/`:

| File | Format | Description |
|---|---|---|
| `dist/hofmann-typescript.js` | ESM | For modern bundlers and `<script type="module">` |
| `dist/hofmann-typescript.umd.cjs` | UMD | For CommonJS environments and direct `<script>` tags |
| `dist/index.d.ts` | TypeScript declarations | Included automatically by bundlers |

`@noble/curves` and `@noble/hashes` are external in the build — they are not bundled and must be present in the consuming project's `node_modules`. `hash-wasm` is a regular dependency and is bundled.

```bash
npm run typecheck   # type-check without emitting files
```

---

## Project Structure

```
hofmann-typescript/
├── src/
│   ├── index.ts                  # Public re-exports
│   ├── crypto/
│   │   ├── primitives.ts         # i2osp, concat, xor, constantTimeEqual, fromHex, toHex
│   │   ├── encoding.ts           # base64Encode/Decode, strToBytes/bytesToStr
│   │   └── hkdf.ts               # hkdfExtract, hkdfExpand, hkdfExpandLabel (SHA-256)
│   ├── oprf/
│   │   ├── suite.ts              # CipherSuite interface; P256_SHA256, P384_SHA384,
│   │   │                         #   P521_SHA512 constants; getCipherSuite()
│   │   ├── client.ts             # blind(), finalize(), deriveKeyPair(), hashToScalar()
│   │   └── http.ts               # OprfHttpClient → POST /oprf, GET /oprf/config
│   └── opaque/
│       ├── types.ts              # Envelope, KE1, KE2, AuthResult, RegistrationRecord, …
│       ├── ksf.ts                # KSF type, identityKsf, argon2idKsf()
│       ├── envelope.ts           # storeEnvelope(), recoverEnvelope() — suite-aware sizes
│       ├── ake.ts                # buildPreamble(), derive3DHKeys(), verifyServerMac(),
│       │                         #   computeClientMac() — suite-aware hash/HMAC/HKDF
│       ├── client.ts             # OpaqueClient(suite?) — crypto only, no HTTP
│       └── http.ts               # OpaqueHttpClient — full HTTP flow, create() factory
├── test/
│   ├── oprf.test.ts              # RFC 9497 vectors + multi-suite constants + round-trips
│   ├── opaque.test.ts            # RFC 9807 vectors + multi-suite round-trips
│   └── integration.test.ts       # Live server tests (skipped without TEST_SERVER_URL)
├── demo.html                     # Interactive browser demo UI
├── demo.ts                       # Demo logic — auto-loads config from server on startup
├── vite.config.ts                # Library build config (ESM + UMD)
└── vite.demo.config.ts           # Dev server config with proxy for demo.html
```

---

## Server Endpoints

For the full REST endpoint listing, request/response format, and server setup, see the
[server configuration guide](../USAGE.md).
