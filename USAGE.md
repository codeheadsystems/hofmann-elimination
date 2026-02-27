# Server Configuration Guide

This document covers all server-side configuration for the Hofmann Dropwizard bundle
(`hofmann-dropwizard`) and the corresponding client-side requirements that must match.

---

## Configuration reference

All fields below are YAML properties in `HofmannConfiguration`.  Every field has a default;
fields marked **required for production** will cause incorrect or insecure behaviour if left
at their default in a real deployment.

### OPAQUE

| Field | Default | Required for production | Description |
|---|---|---|---|
| `opaqueCipherSuite` | `P256_SHA256` | No | Cipher suite for OPAQUE. Accepted values: `P256_SHA256`, `P384_SHA384`, `P521_SHA512`. Must match the client exactly. |
| `context` | `hofmann-opaque-v1` | **Yes** | Application context string bound into the OPAQUE preamble. Must be unique per deployment. Shared between server and client out-of-band. |
| `serverKeySeedHex` | `""` (random) | **Yes** | Hex-encoded 32-byte seed that deterministically derives the server's long-term AKE key pair. Generate with `openssl rand -hex 32`. |
| `oprfSeedHex` | `""` (random) | **Yes** | Hex-encoded 32-byte seed that deterministically derives per-credential OPRF keys. Generate with `openssl rand -hex 32`. Must be set together with `serverKeySeedHex` — providing only one throws `IllegalStateException` on startup. |
| `argon2MemoryKib` | `65536` | **Yes** | Argon2id memory cost in kibibytes. Set to `0` to disable Argon2 (identity KSF — for testing only). See [Argon2id consistency](#argon2id-consistency-between-server-and-client) below. |
| `argon2Iterations` | `3` | **Yes** | Argon2id iteration count. Ignored when `argon2MemoryKib` is `0`. |
| `argon2Parallelism` | `1` | **Yes** | Argon2id parallelism. Ignored when `argon2MemoryKib` is `0`. |

### OPRF (standalone endpoint)

| Field | Default | Required for production | Description |
|---|---|---|---|
| `oprfCipherSuite` | `P256_SHA256` | No | Cipher suite for the standalone `/oprf` endpoint. Independent of `opaqueCipherSuite`. |
| `oprfMasterKeyHex` | `""` (random) | **Yes** | Hex-encoded scalar used as the OPRF master key. Must be a valid non-zero scalar in the chosen curve group. Generate with `openssl rand -hex 32`. An empty value generates a random key on each startup, making OPRF outputs unstable across restarts. |
| `oprfProcessorId` | `hofmann-oprf-v1` | No | Human-readable identifier returned in every OPRF response. Useful for tracing which key produced a given output during key rotation. |

### JWT

| Field | Default | Required for production | Description |
|---|---|---|---|
| `jwtSecretHex` | `""` (random) | **Yes** | Hex-encoded 32-byte HMAC-SHA256 signing secret. Generate with `openssl rand -hex 32`. An empty value generates a random secret on each startup, invalidating all tokens after a restart. |
| `jwtTtlSeconds` | `3600` | No | Token time-to-live in seconds. |
| `jwtIssuer` | `hofmann` | No | Value placed in the JWT `iss` claim. |

### Security

| Field | Default | Required for production | Description |
|---|---|---|---|
| `maxRequestBodyBytes` | `65536` | No | Requests with a `Content-Length` header exceeding this value are rejected with HTTP 413 before the body is read. The largest OPAQUE message is well under 64 KiB; raise this only if you have a specific reason. |

---

## Key material and restart behaviour

`serverKeySeedHex` and `oprfSeedHex` control whether the server's OPAQUE keys are stable
across restarts.

- **Both empty** — keys are randomly generated at startup.  Any registered user's credentials
  become cryptographically invalid when the process restarts.  Suitable for integration tests and
  the `hofmann-testserver` Docker image, where data loss on restart is acceptable.

- **Both set** — keys are derived deterministically from the seeds.  The server's long-term AKE
  public key stays the same across restarts, so registered credentials remain valid.  Required for
  production.

- **Only one set** — the bundle throws `IllegalStateException` on startup.  Both seeds must be
  provided together or both omitted.

The same principle applies to `jwtSecretHex` (tokens survive restart) and `oprfMasterKeyHex`
(OPRF outputs are stable across restarts).

---

## Argon2id consistency between server and client

The Argon2id KSF runs **on the client**, not the server.  The client calls it during both
registration (`finalizeRegistration`) and authentication (`generateKE3`) to derive
`randomizedPwd`:

```
randomizedPwd = HKDF-Extract("", oprfOutput || Argon2id(oprfOutput))
```

The server never executes Argon2id.  It stores only the already-stretched output
(inside the `envelope` and `maskingKey`).  The Argon2id parameters are therefore **not
communicated over the wire** — the client must be configured with the same values the server
was configured with at registration time.

### What happens when parameters mismatch

If the client uses different Argon2id parameters (or identity KSF) from the server's
configuration:

- **Registration appears to succeed** — the server stores whatever the client sends.
- **Authentication always fails** — the client derives a different `randomizedPwd` and
  therefore a different `maskingKey`, so the masked credential response decrypts to garbage.
  The OPAQUE MAC verification fails and the client receives a `SecurityException`.
  The failure is indistinguishable from a wrong password.

This is a silent failure mode that is difficult to debug.

### Parameters that must match exactly

The client and server must agree on all four values simultaneously:

| Server config field | Matching client parameter | `OpaqueClientConfig` factory |
|---|---|---|
| `opaqueCipherSuite` | cipher suite name | `withArgon2id(suiteName, ...)` |
| `context` | context string | `withArgon2id(..., context, ...)` |
| `argon2MemoryKib` | `argon2MemoryKib` | `withArgon2id(..., memory, ...)` |
| `argon2Iterations` | `argon2Iterations` | `withArgon2id(..., iterations, ...)` |
| `argon2Parallelism` | `argon2Parallelism` | `withArgon2id(..., parallelism, ...)` |

### Correct client setup for a production server

```java
// Matches server config: P256_SHA256, context "my-app", Argon2id 65536/3/1
OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
    "P256_SHA256",
    "my-app",   // must equal the server's 'context' field
    65536,      // must equal the server's argon2MemoryKib
    3,          // must equal the server's argon2Iterations
    1           // must equal the server's argon2Parallelism
);
```

### Correct client setup for the hofmann-testserver

```java
// Matches hofmann-testserver/config/config.yml
OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
    "P256_SHA256",
    "hofmann-testserver",
    65536,
    3,
    1
);
```

### Test-only shortcut (identity KSF)

`OpaqueClientConfig.forTesting(context)` uses identity KSF (no Argon2).  It only works
correctly against a server with `argon2MemoryKib: 0`.  Do not use it against the
`hofmann-testserver` (which has Argon2 enabled) or any production server.

### Changing Argon2id parameters

Changing any Argon2id parameter after users have registered **invalidates all existing
registrations**.  Every affected user must re-register from scratch.  Plan parameter
upgrades (e.g., increasing memory cost) as a full re-registration migration.

---

## Dropwizard integration

Add the bundle in your `Application.initialize()`:

```java
// Dev / test — in-memory stores, ephemeral keys, logs prominent warnings
bootstrap.addBundle(new HofmannBundle<>());

// Production — persistent stores, key from config
bootstrap.addBundle(new HofmannBundle<>(myCredentialStore, mySessionStore, null));

// Production with OPRF key rotation
bootstrap.addBundle(new HofmannBundle<>(
    myCredentialStore,
    mySessionStore,
    () -> keyRotationService.currentDetail()));

// Custom SecureRandom (e.g., HSM-backed)
bootstrap.addBundle(new HofmannBundle<>().withSecureRandom(mySecureRandom));
```

`CredentialStore` and `SessionStore` are interfaces in `hofmann-server`.  You must provide
implementations backed by a database or distributed cache for production use.  The bundle's
no-arg constructor uses `InMemoryCredentialStore` and `InMemorySessionStore`, which lose
all data on restart.

When using persistent stores and `processorDetailSupplier = null`, `oprfMasterKeyHex` must
be set in the configuration.  Omitting it throws `IllegalStateException` on startup.

---

## Endpoints registered by the bundle

| Method | Path | Auth required | Description |
|---|---|---|---|
| `POST` | `/opaque/registration/start` | No | Begin OPAQUE registration (returns blinded OPRF evaluation) |
| `POST` | `/opaque/registration/finish` | No | Complete registration (stores credential record) |
| `DELETE` | `/opaque/registration` | Bearer token | Delete a credential record |
| `POST` | `/opaque/auth/start` | No | Begin OPAQUE authentication (KE1 → KE2) |
| `POST` | `/opaque/auth/finish` | No | Complete authentication (KE3 → JWT) |
| `POST` | `/oprf` | No | Standalone OPRF evaluation |

The bundle also registers:
- A health check at `/admin/healthcheck` named `opaque-server` that verifies the server
  public key is a valid compressed EC point.
- A Bearer token authentication filter.  Protect your own routes with `@Auth HofmannPrincipal`.
- A request body size filter (HTTP 413 for oversized payloads).

---

## Local test server

`hofmann-testserver/` provides a Docker Compose setup backed by `HofmannApplication` with
in-memory stores.  Start it with:

```bash
cd hofmann-testserver
docker compose up
```

The default `config.yml` uses Argon2id (65536 KiB / 3 / 1) and stable pre-generated test
keys so the server public key is consistent across container restarts within the same image.
Override individual keys by setting environment variables before running Compose:

```bash
export SERVER_KEY_SEED_HEX=$(openssl rand -hex 32)
export OPRF_SEED_HEX=$(openssl rand -hex 32)
export OPRF_MASTER_KEY_HEX=$(openssl rand -hex 32)
export JWT_SECRET_HEX=$(openssl rand -hex 32)
docker compose up
```

Clients connecting to the testserver must use `OpaqueClientConfig.withArgon2id(...)` as shown
above.  `OpaqueClientConfig.forTesting(...)` will not work because it uses identity KSF.
