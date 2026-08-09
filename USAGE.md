# Server Configuration Guide

Every server-side configuration field for the Hofmann Dropwizard bundle (`hofmann-dropwizard`) and
the Spring Boot starter (`hofmann-springboot`), with defaults and what each one costs you if left
at its default.

If you integrate hofmann-elimination into your own server framework instead, you still need to
supply these values in a way that suits your environment — from an HSM, a secrets manager, or your
database. See [Framework integration](docs/INTEGRATION.md).

> **Server configuration** · [Client configuration](docs/CLIENT_CONFIG.md) · [Framework integration](docs/INTEGRATION.md) · [Key management](docs/KEY_MANAGEMENT.md) · [Doc map](docs/README.md)

**This page is the reference.** The neighbouring guides carry the procedures:

| If you want to | Go to |
|---|---|
| Generate the four secrets, or rotate any of them | [Key management](docs/KEY_MANAGEMENT.md) |
| Configure a Java or TypeScript client, or match Argon2id parameters by hand | [Client configuration](docs/CLIENT_CONFIG.md) |
| Wire the bundle into Dropwizard, Spring Boot or your own stack | [Framework integration](docs/INTEGRATION.md) |
| Implement `CredentialStore` or `SessionStore` | [Framework integration](docs/INTEGRATION.md#implementing-credentialstore) |
| Understand the threat model behind a setting | [SECURITY.md](SECURITY.md) |

---

## Configuration reference

All fields below are YAML properties in `HofmannConfiguration`.  Every field has a default;
fields marked **required for production** will cause incorrect or insecure behaviour if left
at their default in a real deployment.

### OPAQUE

| Field               | Default             | Required for production | Description                                                                                                                                                                                                                          |
|---------------------|---------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opaqueCipherSuite` | `P256_SHA256`       | No                      | Cipher suite for OPAQUE. Accepted values: `P256_SHA256`, `P384_SHA384`, `P521_SHA512`, `RISTRETTO255_SHA512`. Must match the client exactly. **A deployment-time choice, not a knob** — the registration record is suite-specific, so changing it invalidates every existing registration exactly as [changing Argon2id parameters](docs/CLIENT_CONFIG.md#changing-argon2id-parameters) does. See [Timing and Side Channels](SECURITY.md) before choosing. |
| `context`           | `hofmann-opaque-v1` | **Yes**                 | Application context string bound into the OPAQUE preamble. Must be unique per deployment. Shared between server and client out-of-band.                                                                                              |
| `serverKeySeedHex`  | `""` (random)       | **Yes**                 | Hex-encoded 32-byte seed that deterministically derives the server's long-term AKE key pair. Generate with `openssl rand -hex 32`.                                                                                                   |
| `oprfSeedHex`       | `""` (random)       | **Yes**                 | Hex-encoded 32-byte seed that deterministically derives per-credential OPRF keys. Generate with `openssl rand -hex 32`. Must be set together with `serverKeySeedHex` — providing only one throws `IllegalStateException` on startup. |
| `previousServerKeySeedHex` | `""`         | No                      | Previous server key seed for key rotation. Credentials registered under these keys remain authenticatable. See [OPAQUE key rotation](docs/KEY_MANAGEMENT.md#opaque-key-rotation). |
| `previousOprfSeedHex`      | `""`         | No                      | Previous OPRF seed for key rotation. Must be set together with `previousServerKeySeedHex` or both omitted. |
| `argon2MemoryKib`   | `65536`             | **Yes**                 | Argon2id memory cost in kibibytes. Clients refuse anything below 19456 KiB or above 4 GiB — see [Key stretching](#key-stretching). `0` selects the identity KSF (no stretching) and additionally requires `allowIdentityKsf`, without which the server refuses to start; development only. See [Argon2id consistency](docs/CLIENT_CONFIG.md#argon2id-consistency-between-server-and-client). |
| `argon2Iterations`  | `3`                 | **Yes**                 | Argon2id iteration count. Clients refuse below 2 or above 10. Ignored when `argon2MemoryKib` is `0`.                                                                                                                                 |
| `argon2Parallelism` | `1`                 | **Yes**                 | Argon2id parallelism. Clients refuse above 16, and **browser clients require `1`** (hash-wasm is single-threaded). Ignored when `argon2MemoryKib` is `0`.                                                                             |

### OPRF (standalone endpoint)

| Field              | Default           | Required for production | Description                                                                                                                                                                                                                                           |
|--------------------|-------------------|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `oprfCipherSuite`  | `P256_SHA256`     | No                      | Cipher suite for the standalone `/oprf` endpoint. Independent of `opaqueCipherSuite`.                                                                                                                                                                 |
| `oprfMasterKeyHex` | none (required)   | **Yes**                 | Hex-encoded scalar used as the OPRF master key. Generate with `openssl rand -hex 32`. An empty value fails startup with `IllegalStateException`. A key congruent to zero modulo the group order is rejected — every evaluation would return the identity element. A key at or above the group order is accepted and reduced modulo it, which changes no output (scalar multiplication reduces anyway) but logs a warning, since it means the key was generated for a wider range than the suite uses: `openssl rand -hex 32` exceeds ristretto255's order roughly 94% of the time. |
| `oprfProcessorId`  | `hofmann-oprf-v1` | No                      | Human-readable identifier returned in every OPRF response. Useful for tracing which key produced a given output during key rotation.                                                                                                                  |

### JWT

| Field                  | Default       | Required for production | Description                                                                                                                                                                              |
|------------------------|---------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jwtSecretHex`         | `""` (random) | **Yes**                 | Hex-encoded 32-byte HMAC-SHA256 signing secret. Generate with `openssl rand -hex 32`. An empty value generates a random secret on each startup, invalidating all tokens after a restart. |
| `jwtPreviousSecretHex` | `""`          | No                      | Hex-encoded previous signing secret for key rotation. Tokens signed with this key are accepted for verification while new tokens are signed with `jwtSecretHex`. See [JWT key rotation](docs/KEY_MANAGEMENT.md#jwt-key-rotation). |
| `jwtTtlSeconds`        | `3600`        | No                      | Token time-to-live in seconds.                                                                                                                                                           |
| `jwtIssuer`            | `hofmann`     | No                      | Value placed in the JWT `iss` claim.                                                                                                                                                     |

### Security

| Field                   | Default | Required for production | Description |
|-------------------------|---------|-------------------------|-------------|
| `maxRequestBodyBytes`   | `65536` | No | Maximum request body size; requests with a larger body are rejected with HTTP 413. Enforced two ways, so a chunked body cannot evade it: a declared `Content-Length` over the limit is rejected before the body is read, and the request stream is bounded as it is read for bodies that declare no length. The batched VOPRF/POPRF endpoints carry their own tighter limit of 17,024 bytes, derived from the batch cap of 64. The largest OPAQUE message is well under 64 KiB; raise this only if you have a specific reason. |
| `trustForwardedHeaders` | `false` | No | Derives the client IP for origin rate limiting from `X-Forwarded-For` instead of the socket peer address. **Only safe behind a trusted proxy that overwrites the header** rather than appending to a client-supplied one — otherwise a single source can mint unlimited distinct rate-limit keys and escape the limiter entirely. |

### API documentation (Dropwizard only)

| Field           | Default      | Required for production | Description |
|-----------------|--------------|-------------------------|-------------|
| `serveApiDocs`  | `false`      | No | Serves an embedded Swagger UI over the OPAQUE and OPRF OpenAPI specs. Off by default because a library should not register a servlet on your server without being asked, and a consumer with their own `/api-docs` mapping would collide with it. When enabled, `ApiDocsSecurityHeadersFilter` is installed on the same path — the servlet sits outside the JAX-RS filter chain, so it would otherwise get no security headers at all. |
| `apiDocsPath`   | `/api-docs`  | No | Path prefix the UI is mounted under when `serveApiDocs` is enabled. Configurable so a consumer already serving something at `/api-docs` can move these out of the way. |

The Spring Boot integration has no equivalent — it does not serve API docs. Use the
[hosted Swagger UI](https://codeheadsystems.github.io/hofmann-elimination/api-docs.html) or the raw
specs in `docs/` instead.

### Development-only escape hatches

Two flags exist to let a local server start in a state a production server must never be in. Both
default to `false`, and in both cases the default is what makes the server refuse to start rather
than proceed in that state — the refusal is the feature.

| Field                | Default | Required for production | Description |
|----------------------|---------|-------------------------|-------------|
| `allowIdentityKsf`   | `false` | No — **never enable in production** | Permits running with **no key stretching** (`argon2MemoryKib: 0`). Without a KSF a stolen registration record is offline-crackable at the speed of a bare hash. |
| `allowEphemeralKeys` | `false` | No — **never enable in production** | Permits starting with no configured key material, generating random keys instead. Every registration is invalidated on restart, and in a multi-node deployment credentials registered against one node cannot authenticate against another. |

### Key stretching

The Argon2id parameters live in the [OPAQUE table](#opaque) above. They are listed there rather
than here because that is where you are when you set them — this section exists to explain the one
thing the table cannot: **the client takes these parameters from the server** via
`GET /opaque/config`, and polices them.

The client accepts at least 19456 KiB and 2 iterations (the OWASP Argon2id minimum at `t=2, p=1`),
and at most 4 GiB, 10 iterations and 16 lanes — the upper bounds are denial-of-service hardening
rather than a security floor. Configure the server outside that window and every client throws
`IllegalStateException` on first use. Why the client polices the server at all, and how to opt out
for a development server, is in [SECURITY.md](SECURITY.md).

### Verifiable OPRF modes (RFC 9497)

Both modes are off until you configure a key. Until then the endpoint answers 404 — not 501,
because the resource is mounted and this deployment simply does not offer the mode. There is
deliberately no ephemeral fallback: clients pin the server's public key and check proofs against
it, so a key regenerated on restart would silently invalidate every pinned key.

**Generate a separate key for each mode with `openssl rand -hex 32`, and do not reuse
`oprfMasterKeyHex`.** RFC 9497 puts the mode byte in every domain-separation tag, so one secret
serving two modes computes two different functions under two different tag sets — which is not a
compromise between them, just two unrelated outputs from one secret.

| Field                | Default | Required for production | Description |
|----------------------|---------|-------------------------|-------------|
| `voprfMasterKeyHex`  | `""`    | No | VOPRF (mode 0x01) key, hex. `openssl rand -hex 32`. Empty or absent disables `POST /oprf/verifiable`. |
| `poprfMasterKeyHex`  | `""`    | No | POPRF (mode 0x02) key, hex. `openssl rand -hex 32`. Empty or absent disables `POST /oprf/partially-oblivious`. |

> **Dropwizard only:** `corsAllowedOrigins` (default empty, i.e. CORS disabled) lists the origins
> allowed to call the OPAQUE and OPRF endpoints from a browser. The Spring integration configures
> CORS through the `hofmannCorsConfigurationSource` bean instead; override that bean to customise
> it.

---

---

## Key material and restart behaviour

`serverKeySeedHex` and `oprfSeedHex` control whether the server's OPAQUE keys are stable
across restarts.

- **Both empty** — the server **refuses to start** unless `allowEphemeralKeys` is also set. With
  that flag, keys are randomly generated at startup and any registered user's credentials become
  cryptographically invalid when the process restarts. Suitable for integration tests and the
  `hofmann-testserver` Docker image, where data loss on restart is acceptable; never for
  production, where it also means credentials registered against one node cannot authenticate
  against another.

- **Both set** — keys are derived deterministically from the seeds.  The server's long-term AKE
  public key stays the same across restarts, so registered credentials remain valid.  Required for
  production.

- **Only one set** — the bundle throws `IllegalStateException` on startup.  Both seeds must be
  provided together or both omitted.

The same principle applies to `jwtSecretHex` (tokens survive restart) and `oprfMasterKeyHex`
(OPRF outputs are stable across restarts).

---

## Endpoints registered by the bundle

| Method   | Path                          | Auth required | Description                                                 |
|----------|-------------------------------|---------------|-------------------------------------------------------------|
| `GET`    | `/opaque/config`              | No            | Returns OPAQUE cipher suite, context, and Argon2id params   |
| `POST`   | `/opaque/registration/start`  | No            | Begin OPAQUE registration (returns blinded OPRF evaluation) |
| `POST`   | `/opaque/registration/finish` | No            | Complete registration (stores credential record)            |
| `DELETE` | `/opaque/registration`        | Bearer token  | Delete a credential record                                  |
| `POST`   | `/opaque/auth/start`          | No            | Begin OPAQUE authentication (KE1 → KE2)                     |
| `POST`   | `/opaque/auth/finish`         | No            | Complete authentication (KE3 → JWT)                         |
| `GET`    | `/oprf/config`                | No            | Returns OPRF cipher suite name                              |
| `POST`   | `/oprf`                       | No            | Standalone OPRF evaluation (base mode, 0x00)                |
| `POST`   | `/oprf/verifiable`            | No            | VOPRF batch evaluation with a DLEQ proof (mode 0x01). **404 unless `voprfMasterKeyHex` is set** |
| `POST`   | `/oprf/partially-oblivious`   | No            | POPRF batch evaluation under a public input (mode 0x02). **404 unless `poprfMasterKeyHex` is set** |

The bundle also registers:
- A health check at `/admin/healthcheck` named `opaque-server` that verifies the server
  public key is a valid compressed EC point.
- A Bearer token authentication filter.  Protect your own routes with `@Auth HofmannPrincipal`.
- A request body size filter (HTTP 413 for oversized payloads, including chunked bodies
  that declare no `Content-Length`). The two batched OPRF endpoints get a tighter limit.

---

## Local test server

`hofmann-testserver/` provides a Docker Compose setup backed by `HofmannApplication` with
in-memory stores.  Start it with:

```bash
cd hofmann-testserver
docker compose up
```

The default `config.yml` uses Argon2id (65536 KiB / 3 / 1) and sets `allowEphemeralKeys: true`,
so with no environment variables set the server generates random key material at startup and
runs. Nothing is committed as a key — a fallback in a file that ships inside a published image is
a working key shared by every deployment of that image.

The cost of the ephemeral default is stated in the startup warning: **every registration is
invalidated when the container restarts**, and two nodes cannot authenticate each other's
credentials. Set the keys to get a server public key that survives a restart:

```bash
export SERVER_KEY_SEED_HEX=$(openssl rand -hex 32)
export OPRF_SEED_HEX=$(openssl rand -hex 32)
export OPRF_MASTER_KEY_HEX=$(openssl rand -hex 32)
export JWT_SECRET_HEX=$(openssl rand -hex 32)
docker compose up
```

To make the test server behave like production and refuse to start when the keys are missing,
export `ALLOW_EPHEMERAL_KEYS=false`.

Clients connecting to the testserver can use `HofmannOpaqueClientManager(accessor)` without
any manual config — the manager fetches the cipher suite, context, and Argon2id parameters
automatically from `GET /opaque/config` on first use.  If you are constructing
`OpaqueClientConfig` directly (e.g. for a CLI override), use `withArgon2id(...)` — not
`forTesting(...)`, which uses the identity KSF and will fail against a server with Argon2
enabled.
