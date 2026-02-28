# hofmann-typescript

Browser/Node TypeScript client for the [Hofmann Elimination](../README.md) OPRF and OPAQUE server.

Implements:
- **RFC 9497** — Oblivious Pseudorandom Functions (OPRF), P-256/SHA-256
- **RFC 9807** — OPAQUE-3DH password-authenticated key exchange

All cryptography is built on [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes). No native bindings, no WebAssembly (except the optional Argon2id KSF via `hash-wasm`).

> **Security notice:** This implementation has not undergone a formal security audit. See the [parent project](../README.md) for full details.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
  - [OpaqueHttpClient](#opaquehttpclient)
  - [OprfHttpClient](#oprfhttpclient)
  - [OpaqueClient (low-level)](#opaqueclient-low-level)
  - [Key Stretching Functions (KSF)](#key-stretching-functions-ksf)
- [Matching Server Configuration](#matching-server-configuration)
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
| `@noble/curves` | P-256 elliptic curve arithmetic, hash-to-curve |
| `@noble/hashes` | SHA-256, HMAC, HKDF |
| `hash-wasm` | Argon2id key stretching (only loaded when used) |

---

## Quick Start

### OPAQUE registration and login

```typescript
import { OpaqueHttpClient, argon2idKsf } from 'hofmann-typescript';

const client = new OpaqueHttpClient('https://your-server.example.com', {
  context: 'your-app-context',       // must match server config exactly
  ksf: argon2idKsf(65536, 3, 1),    // must match server Argon2id params exactly
});

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

const client = new OprfHttpClient('https://your-server.example.com');
const result = await client.evaluate(strToBytes('my-secret-input'));
// result is a stable 32-byte Uint8Array — same every time for the same input and server key
```

---

## Configuration

The two parameters that **must exactly match the server's configuration** are the **context string** and the **Argon2id parameters**. A mismatch causes silent authentication failure that is indistinguishable from a wrong password.

### Reading the server's config

For a Dropwizard server, look at the YAML configuration file:

```yaml
# hofmann-testserver/config/config.yml (example)
context: hofmann-testserver
argon2MemoryKib: 65536
argon2Iterations: 3
argon2Parallelism: 1
```

The matching TypeScript client:

```typescript
import { OpaqueHttpClient, argon2idKsf } from 'hofmann-typescript';

const client = new OpaqueHttpClient('http://localhost:8080', {
  context: 'hofmann-testserver',
  ksf: argon2idKsf(65536, 3, 1),
});
```

### Identity KSF (test servers only)

If the server has `argon2MemoryKib: 0` (identity KSF, no Argon2), omit the `ksf` option or pass `identityKsf`:

```typescript
import { OpaqueHttpClient, identityKsf } from 'hofmann-typescript';

const client = new OpaqueHttpClient('http://localhost:8080', {
  context: 'my-test-context',
  ksf: identityKsf,   // or simply omit ksf entirely
});
```

> **Do not use identity KSF against a production server.** It disables password hardening.

---

## API Reference

### OpaqueHttpClient

The main entry point. Handles the full OPAQUE-3DH protocol over HTTP, communicating with the hofmann-server REST endpoints.

```typescript
import { OpaqueHttpClient, argon2idKsf } from 'hofmann-typescript';

const client = new OpaqueHttpClient(baseUrl: string, options?: OpaqueHttpClientOptions);
```

**`OpaqueHttpClientOptions`**

| Field | Type | Default | Description |
|---|---|---|---|
| `context` | `string` | `""` | OPAQUE protocol context. Must match `context` in the server config. |
| `ksf` | `KSF` | `identityKsf` | Key stretching function. Use `argon2idKsf(...)` for production servers. |

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

Throws an `Error` if:
- The password is incorrect (server MAC verification fails before KE3 is sent)
- The server rejects the client MAC (authentication rejected server-side)
- Network errors or non-2xx HTTP responses

#### `deleteRegistration(credentialId, token): Promise<void>`

Sends `DELETE /opaque/registration` with the `Authorization: Bearer <token>` header.

```typescript
await client.deleteRegistration('alice@example.com', token);
```

---

### OprfHttpClient

Standalone OPRF client for the `/oprf` endpoint. Useful when you want a server-keyed pseudorandom function without the full OPAQUE flow (e.g., for generating stable, private identifiers from sensitive input).

```typescript
import { OprfHttpClient } from 'hofmann-typescript';
import { strToBytes } from 'hofmann-typescript';

const client = new OprfHttpClient('https://your-server.example.com');
const output: Uint8Array = await client.evaluate(strToBytes('my-input'));
```

`evaluate(input: Uint8Array): Promise<Uint8Array>` returns a stable 32-byte value. The same input always produces the same output for a given server key. The server learns nothing about `input` — it sees only the blinded EC point.

---

### OpaqueClient (low-level)

The `OpaqueClient` class implements the OPAQUE cryptographic operations without any HTTP transport. Use this if you need to integrate with a custom transport layer or build server-side logic in TypeScript.

```typescript
import { OpaqueClient, identityKsf, argon2idKsf } from 'hofmann-typescript';
import type { KSF } from 'hofmann-typescript';

const client = new OpaqueClient();
const ksf: KSF = argon2idKsf(65536, 3, 1);

// ── Registration ────────────────────────────────────────────────────────────

// Step 1a: create registration request
const regState = client.createRegistrationRequest(passwordBytes);
// regState.blindedElement → send to server

// Step 1c: finalize registration (after receiving server response)
const record = await client.finalizeRegistration(
  regState,
  { evaluatedElement, serverPublicKey },  // from server
  null,         // serverIdentity (null = use serverPublicKey)
  null,         // clientIdentity (null = use derived clientPublicKey)
  undefined,    // envelopeNonce (undefined = random)
  ksf           // key stretching function
);
// record.clientPublicKey, record.maskingKey, record.envelope → upload to server

// ── Authentication ──────────────────────────────────────────────────────────

// Step 2a: generate KE1
const { state, ke1Bytes } = client.generateKE1(passwordBytes);
// state.blindedElement, state.clientNonce, state.clientAkePublicKey → send to server

// Step 2c: generate KE3 after receiving KE2 from server
const authResult = await client.generateKE3(
  state,
  ke2,          // KE2 object with evaluatedElement, maskingNonce, etc.
  null,         // clientIdentity
  null,         // serverIdentity
  contextBytes, // application context (must match server)
  ksf           // key stretching function
);
// authResult.clientMac → send to server as KE3
// authResult.sessionKey → shared session key (32 bytes)
// authResult.exportKey → optional export key (32 bytes)
```

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

The KSF is applied to the raw OPRF output before it is fed into HKDF to produce `randomizedPwd`. The client and server must use the same KSF and parameters at all times — changing them after registration invalidates all existing credentials.

```typescript
import { identityKsf, argon2idKsf, type KSF } from 'hofmann-typescript';
```

#### `identityKsf`

No stretching — the OPRF output is used directly. Appropriate only for testing with servers configured with `argon2MemoryKib: 0`. This is the default when `ksf` is omitted from `OpaqueHttpClientOptions`.

#### `argon2idKsf(memoryKib, iterations, parallelism): KSF`

Returns an Argon2id key stretching function. Uses a 32-byte all-zero salt and outputs 32 bytes, matching the server's implementation.

```typescript
// Matching hofmann-testserver defaults
const ksf = argon2idKsf(65536, 3, 1);

// Custom parameters
const ksf = argon2idKsf(
  131072,  // 128 MiB memory
  4,       // iterations
  2        // parallelism
);
```

`hash-wasm` is loaded on demand the first time `argon2idKsf` is invoked; there is no startup cost if identity KSF is used.

#### Custom KSF

The `KSF` type is `(input: Uint8Array) => Promise<Uint8Array>`. You can supply any async function:

```typescript
const myKsf: KSF = async (input) => {
  // custom key stretching...
  return stretchedOutput;
};
```

---

## Matching Server Configuration

The `context` string and Argon2id parameters **must be identical** between client and server.
A mismatch causes silent authentication failure indistinguishable from a wrong password.

| Server YAML field | Client option |
|---|---|
| `context` | `options.context` |
| `argon2MemoryKib` | First arg to `argon2idKsf(...)` |
| `argon2Iterations` | Second arg to `argon2idKsf(...)` |
| `argon2Parallelism` | Third arg to `argon2idKsf(...)` |

For a full explanation of the failure modes and migration considerations, see
[USAGE.md — Argon2id consistency](../USAGE.md#argon2id-consistency-between-server-and-client).

---

## Interactive Demo

A browser-based demo page is included for manual testing against a running server.

```bash
npm run demo
```

This starts a Vite dev server at `http://localhost:5173/demo.html` (opens automatically) and proxies `/opaque` and `/oprf` requests to `http://localhost:8080`, avoiding CORS issues.

To target a different server:

```bash
HOFMANN_SERVER=http://other-server:8080 npm run demo
```

The demo provides:
- **OPAQUE Registration** — enter credential ID and password, click Register
- **OPAQUE Authentication** — returns a JWT token (auto-fills the Delete form)
- **Delete Registration** — removes the credential (requires the JWT from authentication)
- **Standalone OPRF** — evaluate an arbitrary plaintext through the server's OPRF key
- **Activity log** — timestamped protocol step log

The demo defaults match `hofmann-testserver/config/config.yml`:
- Context: `hofmann-testserver`
- Argon2id: 65536 KiB / 3 iterations / 1 parallelism

If your server uses different settings, update the fields in the **Server Configuration** panel before registering.

---

## Running Tests

### RFC vector tests (no server required)

```bash
npm test
```

Runs 17 tests validating the cryptographic implementation against official CFRG test vectors:
- **`test/oprf.test.ts`** — RFC 9497 P-256/SHA-256 vectors (DSTs, `blind`, `finalize`, `deriveKeyPair`)
- **`test/opaque.test.ts`** — RFC 9807 OPAQUE-3DH vectors (registration records, KE1 bytes, server MAC, full AKE round-trip)

### Integration tests (requires running server)

```bash
TEST_SERVER_URL=http://localhost:8080 npm test -- integration
```

Runs a full register → authenticate → wrong-password-rejection → delete flow against the live server. Each OPAQUE operation has a 30-second timeout to accommodate Argon2id processing time.

The integration tests are skipped automatically when `TEST_SERVER_URL` is not set, so `npm test` without it always runs only the offline RFC vector tests.

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
│   │   └── hkdf.ts               # hkdfExtract, hkdfExpand, hkdfExpandLabel
│   ├── oprf/
│   │   ├── suite.ts              # DST constants, Nh/Npk/Nsk/Nn/Nm
│   │   ├── client.ts             # blind(), finalize(), deriveKeyPair(), hashToScalar()
│   │   └── http.ts               # OprfHttpClient → POST /oprf
│   └── opaque/
│       ├── types.ts              # Envelope, KE1, KE2, AuthResult, RegistrationRecord, …
│       ├── ksf.ts                # KSF type, identityKsf, argon2idKsf()
│       ├── envelope.ts           # storeEnvelope(), recoverEnvelope()
│       ├── ake.ts                # buildPreamble(), derive3DHKeys(), verifyServerMac(), computeClientMac()
│       ├── client.ts             # OpaqueClient — crypto only, no HTTP
│       └── http.ts               # OpaqueHttpClient — full HTTP flow
├── test/
│   ├── oprf.test.ts              # RFC 9497 P-256 test vectors
│   ├── opaque.test.ts            # RFC 9807 OPAQUE test vectors
│   └── integration.test.ts       # Live server tests (skipped without TEST_SERVER_URL)
├── demo.html                     # Interactive browser demo UI
├── demo.ts                       # Demo application logic
├── vite.config.ts                # Library build config (ESM + UMD)
└── vite.demo.config.ts           # Dev server config with proxy for demo.html
```

---

## Server Endpoints

For the full REST endpoint listing, request/response format, and server setup, see the
[server configuration guide](../USAGE.md).
