# Server Configuration Guide

This document covers all server-side configuration for the Hofmann Dropwizard bundle
(`hofmann-dropwizard`) and the corresponding client-side requirements that must match.

If you integrate hofmann-elimination into your own server framework instead of using the Dropwizard bundle,
you should have a mechanism to provide these configurations suitable for your environment. 
Some facilities will use an HSM to provide these keys, or from the database. 

---

## Configuration reference

All fields below are YAML properties in `HofmannConfiguration`.  Every field has a default;
fields marked **required for production** will cause incorrect or insecure behaviour if left
at their default in a real deployment.

### OPAQUE

| Field               | Default             | Required for production | Description                                                                                                                                                                                                                          |
|---------------------|---------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opaqueCipherSuite` | `P256_SHA256`       | No                      | Cipher suite for OPAQUE. Accepted values: `P256_SHA256`, `P384_SHA384`, `P521_SHA512`, `RISTRETTO255_SHA512`. Must match the client exactly. **A deployment-time choice, not a knob** — the registration record is suite-specific, so changing it invalidates every existing registration exactly as [changing Argon2id parameters](#changing-argon2id-parameters) does. See [Timing and Side Channels](SECURITY.md) before choosing. |
| `context`           | `hofmann-opaque-v1` | **Yes**                 | Application context string bound into the OPAQUE preamble. Must be unique per deployment. Shared between server and client out-of-band.                                                                                              |
| `serverKeySeedHex`  | `""` (random)       | **Yes**                 | Hex-encoded 32-byte seed that deterministically derives the server's long-term AKE key pair. Generate with `openssl rand -hex 32`.                                                                                                   |
| `oprfSeedHex`       | `""` (random)       | **Yes**                 | Hex-encoded 32-byte seed that deterministically derives per-credential OPRF keys. Generate with `openssl rand -hex 32`. Must be set together with `serverKeySeedHex` — providing only one throws `IllegalStateException` on startup. |
| `previousServerKeySeedHex` | `""`         | No                      | Previous server key seed for key rotation. Credentials registered under these keys remain authenticatable. See [OPAQUE key rotation](#opaque-key-rotation). |
| `previousOprfSeedHex`      | `""`         | No                      | Previous OPRF seed for key rotation. Must be set together with `previousServerKeySeedHex` or both omitted. |
| `argon2MemoryKib`   | `65536`             | **Yes**                 | Argon2id memory cost in kibibytes. Clients refuse anything below 19456 KiB or above 4 GiB — see [Key stretching](#key-stretching). `0` selects the identity KSF (no stretching) and additionally requires `allowIdentityKsf`, without which the server refuses to start; development only. See [Argon2id consistency](#argon2id-consistency-between-server-and-client). |
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
| `jwtPreviousSecretHex` | `""`          | No                      | Hex-encoded previous signing secret for key rotation. Tokens signed with this key are accepted for verification while new tokens are signed with `jwtSecretHex`. See [JWT key rotation](#jwt-key-rotation). |
| `jwtTtlSeconds`        | `3600`        | No                      | Token time-to-live in seconds.                                                                                                                                                           |
| `jwtIssuer`            | `hofmann`     | No                      | Value placed in the JWT `iss` claim.                                                                                                                                                     |

### Security

| Field                   | Default | Required for production | Description |
|-------------------------|---------|-------------------------|-------------|
| `maxRequestBodyBytes`   | `65536` | No | Maximum request body size; requests with a larger body are rejected with HTTP 413. Enforced two ways, so a chunked body cannot evade it: a declared `Content-Length` over the limit is rejected before the body is read, and the request stream is bounded as it is read for bodies that declare no length. The batched VOPRF/POPRF endpoints carry their own tighter limit of 17,024 bytes, derived from the batch cap of 64. The largest OPAQUE message is well under 64 KiB; raise this only if you have a specific reason. |
| `trustForwardedHeaders` | `false` | No | Derives the client IP for origin rate limiting from `X-Forwarded-For` instead of the socket peer address. **Only safe behind a trusted proxy that overwrites the header** rather than appending to a client-supplied one — otherwise a single source can mint unlimited distinct rate-limit keys and escape the limiter entirely. |

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

## Client configuration

### Auto-configuration (recommended)

Both `HofmannOpaqueClientManager` and `HofmannOprfClientManager` auto-configure themselves
on first use by calling the server's config endpoint (`GET /opaque/config` or
`GET /oprf/config`).  The response is cached per server, so the endpoint is hit exactly
once regardless of how many operations follow.

```java
// OPAQUE — no config needed; cipher suite, context, and Argon2id params
// are fetched automatically from GET /opaque/config on first use.
HofmannOpaqueClientManager opaqueManager =
    new HofmannOpaqueClientManager(opaqueAccessor);

// OPRF — cipher suite fetched from GET /oprf/config on first use.
HofmannOprfClientManager oprfManager =
    new HofmannOprfClientManager(oprfAccessor);
```

Both classes are `@Singleton`-annotated and suitable for injection by Dagger, Guice, or
Spring.  The accessor requires only a `Map<ServerIdentifier, ServerConnectionInfo>` that
maps each logical server name to its base URL — no cipher suite or Argon2id parameters
needed.

### TypeScript / browser

The TypeScript clients have matching factory methods:

```typescript
// OPAQUE — fetches /opaque/config and configures KSF automatically
const opaqueClient = await OpaqueHttpClient.create('https://api.example.com');
// opaqueClient.configResponse holds the parsed OpaqueConfigResponseDto if needed

// OPRF — fetches /oprf/config and stores it in cachedConfig
const oprfClient = await OprfHttpClient.create('https://api.example.com');
// oprfClient.cachedConfig holds { cipherSuite: string } if needed
```

### Per-server config overrides (CLI / advanced use)

For tools that must work offline or where specific parameters must be pinned, supply a
`Map<ServerIdentifier, OpaqueClientConfig>` (or `OprfClientConfig`) as the second argument.
Servers present in the map skip the auto-fetch; others still auto-fetch.

```java
// Pins exact parameters for one server; other servers are still auto-fetched.
Map<ServerIdentifier, OpaqueClientConfig> overrides = Map.of(
    myServerId,
    OpaqueClientConfig.withArgon2id("P256_SHA256", "my-app", 65536, 3, 1)
);
HofmannOpaqueClientManager manager =
    new HofmannOpaqueClientManager(accessor, overrides);
```

This is the pattern used by the `OpaqueCli` / `OprfCli` command-line tools.

---

## Argon2id consistency between server and client

The Argon2id KSF runs **on the client**, not the server.  The client calls it during both
registration (`finalizeRegistration`) and authentication (`generateKE3`) to derive
`randomizedPwd`:

```
randomizedPwd = HKDF-Extract("", oprfOutput || Argon2id(oprfOutput))
```

The server never executes Argon2id.  It stores only the already-stretched output
(inside the `envelope` and `maskingKey`).

**When using auto-configuration** (the default), the client fetches these parameters from
`GET /opaque/config` and applies them automatically.  No manual alignment is required.

**When using config overrides**, the parameters must match the server exactly.  A mismatch
causes silent authentication failures:

- **Registration appears to succeed** — the server stores whatever the client sends.
- **Authentication always fails** — the client derives a different `randomizedPwd` and
  therefore a different `maskingKey`.  The OPAQUE MAC check fails with a `SecurityException`,
  indistinguishable from a wrong password.

### Parameters that must match (override path only)

| Server config field | `OpaqueClientConfig` factory argument |
|---------------------|---------------------------------------|
| `opaqueCipherSuite` | `withArgon2id(suiteName, ...)`        |
| `context`           | `withArgon2id(..., context, ...)`     |
| `argon2MemoryKib`   | `withArgon2id(..., memory, ...)`      |
| `argon2Iterations`  | `withArgon2id(..., iterations, ...)`  |
| `argon2Parallelism` | `withArgon2id(..., parallelism, ...)` |

### Test-only shortcut (identity KSF)

`OpaqueClientConfig.forTesting(context)` uses identity KSF (no Argon2). It only works against a
server with `argon2MemoryKib: 0`, which additionally requires `allowIdentityKsf` or the server
refuses to start. A client negotiating configuration from such a server also needs
`allowWeakServerKsf` — see [SECURITY.md](SECURITY.md). Do not use it against the
`hofmann-testserver` (which has Argon2 enabled) or any production server.

### Changing Argon2id parameters

Changing any Argon2id parameter after users have registered **invalidates all existing
registrations**.  Every affected user must re-register from scratch.  Plan parameter
upgrades (e.g., increasing memory cost) as a full re-registration migration.

---

## Dropwizard integration

Add the bundle in your `Application.initialize()`:

```java
// Dev / test — in-memory stores. Ephemeral keys additionally require allowEphemeralKeys
// in configuration; without it the server refuses to start rather than warning.
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

## Spring Boot integration

Add the autoconfiguration dependency:

```groovy
dependencies {
    implementation 'com.codeheadsystems.hofmann:hofmann-springboot:<version>'
}
```

Autoconfiguration activates automatically — the controllers, security configuration and health
indicator are registered by the autoconfiguration itself, so no component scanning of
`com.codeheadsystems.hofmann.springboot` is required. Most beans are `@ConditionalOnMissingBean`
— override those by declaring your own `@Bean`:

> **If your application declares its own `SecurityFilterChain`**, Hofmann's default chain backs
> off entirely rather than competing with it. Two chains are applied in order and the first match
> wins per request, so a library chain that stayed registered would be incompatible with yours —
> on Spring Security 6.2+ two any-request chains fail fast with `UnreachableFilterChainException`
> and the application will not start.
>
> **Taking over means taking over completely.** The back-off triggers on the *presence* of a
> chain, not on what it matches. A chain scoped with `securityMatcher("/api/**")` still displaces
> Hofmann's, and every URL outside that matcher is then served with **no chain at all** — a
> fail-open gap in your application. Prefer one chain ending in `anyRequest().authenticated()`
> over a scoped one, unless you have deliberately arranged coverage for the remainder.
>
> When you take over: permit `/opaque/**` and `/oprf/**` (the OPAQUE handshake is how a caller
> obtains a token, so requiring one to reach it would be circular), permit the `ERROR` dispatch to
> your error path so 400 / 429 / 503 responses are not rewritten as 401, and wire in the
> `JwtAuthenticationFilter` bean, which remains available for exactly this purpose.
>
> Note also that adopting Hofmann's default chain makes **every** URL in your application require
> a Hofmann JWT unless you permit it explicitly — including endpoints you intend to be public.

```java
// Persistent credential store backed by your database
@Bean
public CredentialStore credentialStore(MyDatabaseRepository repo) {
    return new MyDatabaseCredentialStore(repo);
}

// Persistent session store backed by Redis
@Bean
public SessionStore sessionStore(RedisTemplate<String, byte[]> redis) {
    return new RedisSessionStore(redis);
}

// HSM-backed random source
@Bean
public SecureRandom secureRandom() {
    return myHsmSecureRandom();
}

// OPRF key rotation via dynamic supplier
@Bean
public Supplier<ServerProcessorDetail> serverProcessorDetailSupplier(KeyRotationService svc) {
    return () -> new ServerProcessorDetail(svc.currentKey(), svc.currentKeyId());
}

// JWT key rotation via dynamic supplier
@Bean
public Supplier<JwtKeyDetail> jwtKeyDetailSupplier(MySecretsManager secrets) {
    return () -> new JwtKeyDetail(secrets.currentJwtKey(), secrets.previousJwtKey());
}
```

Configure in `application.yml` using the same field names as the Dropwizard YAML table above, prefixed with `hofmann.`:

```yaml
hofmann:
  opaque-cipher-suite: P256_SHA256
  context: my-app-v1
  server-key-seed-hex: <output of openssl rand -hex 32>
  oprf-seed-hex: <output of openssl rand -hex 32>
  oprf-master-key-hex: <output of openssl rand -hex 32>
  jwt-secret-hex: <output of openssl rand -hex 32>
  jwt-previous-secret-hex: ""   # set to old jwt-secret-hex during key rotation
  argon2-memory-kib: 65536
  argon2-iterations: 3
  argon2-parallelism: 1
```

---

## Custom / bare framework integration

If you are not using Dropwizard or Spring Boot, add the framework-agnostic server module:

```groovy
dependencies {
    implementation 'com.codeheadsystems.hofmann:hofmann-server:<version>'
}
```

Then wire the protocol stack yourself:

```java
import static java.nio.charset.StandardCharsets.UTF_8;

// 1. Choose cipher suite and build config
OpaqueConfig config = OpaqueConfig.withArgon2id(
    "my-app-v1".getBytes(UTF_8),   // context — must match every client
    65536, 3, 1                     // Argon2id memory KiB / iterations / parallelism
);

// 2. Derive the server key pair and OPRF seed from hex seeds
byte[] serverKeySeed = hexToBytes(env.getRequired("SERVER_KEY_SEED_HEX"));
byte[] oprfSeed      = hexToBytes(env.getRequired("OPRF_SEED_HEX"));
AkeKeyPair kp = config.cipherSuite().deriveAkeKeyPair(serverKeySeed);
Server server = new Server(kp.privateKeyBytes(), kp.publicKeyBytes(), oprfSeed, config);

// 3. Build the standalone OPRF supplier (supports hot key rotation)
BigInteger masterKey = new BigInteger(1, hexToBytes(env.getRequired("OPRF_MASTER_KEY_HEX")));
Supplier<ServerProcessorDetail> oprfSupplier =
    () -> new ServerProcessorDetail(masterKey, "key-v1");

// 4. Provide persistent credential and session stores
CredentialStore credentialStore = new MyDatabaseCredentialStore(dataSource);
SessionStore    sessionStore    = new MyRedisSessionStore(redisClient);

// 5. Build the JWT manager (supports key rotation via Supplier<JwtKeyDetail>)
byte[] jwtSecret = hexToBytes(env.getRequired("JWT_SECRET_HEX"));
JwtManager jwt   = new JwtManager(jwtSecret, "my-app", 3600L, sessionStore);

// 6. Build the framework-agnostic protocol manager
HofmannOpaqueServerManager manager =
    new HofmannOpaqueServerManager(server, credentialStore, jwt);

// 7. Optionally build the standalone OPRF manager
OprfServerManager oprfManager = new OprfServerManager(
    OprfCipherSuite.P256_SHA256, oprfSupplier);
```

Expose the manager methods through your own HTTP layer.  Exception mapping:

| Exception thrown           | HTTP status             |
|----------------------------|-------------------------|
| `IllegalArgumentException` | 400 Bad Request         |
| `SecurityException`        | 401 Unauthorized        |
| `IllegalStateException`    | 503 Service Unavailable |

---

## Implementing CredentialStore

`CredentialStore` persists one `RegistrationRecord` per user.  The key is a `credentialIdentifier` byte array — the user's canonical, stable identifier (see [Credential identifier](#credential-identifier) below).

```java
public interface CredentialStore {
    void                         store(byte[] credentialIdentifier, RegistrationRecord record);
    Optional<RegistrationRecord> load(byte[] credentialIdentifier);
    void                         delete(byte[] credentialIdentifier);
}
```

All three methods must be thread-safe.  A minimal JDBC implementation:

```java
public class JdbcCredentialStore implements CredentialStore {

    public void store(byte[] id, RegistrationRecord record) {
        // UPSERT: id (BYTEA primary key), record_bytes (BYTEA)
        jdbcTemplate.update(
            "INSERT INTO credentials(id, record_bytes) VALUES (?, ?) " +
            "ON CONFLICT(id) DO UPDATE SET record_bytes = EXCLUDED.record_bytes",
            id, record.serialize());
    }

    public Optional<RegistrationRecord> load(byte[] id) {
        List<byte[]> rows = jdbcTemplate.query(
            "SELECT record_bytes FROM credentials WHERE id = ?",
            (rs, n) -> rs.getBytes(1), id);
        return rows.isEmpty()
            ? Optional.empty()
            : Optional.of(RegistrationRecord.deserialize(rows.get(0)));
    }

    public void delete(byte[] id) {
        jdbcTemplate.update("DELETE FROM credentials WHERE id = ?", id);
    }
}
```

Record size guide: a `RegistrationRecord` serializes to approximately `Npk + Nh + 96` bytes.
For P-256 that is roughly 160 bytes; for P-521 roughly 224 bytes.  A `BYTEA` / `BLOB` column of 512 bytes is more than sufficient for all supported cipher suites.

---

## Implementing SessionStore

`SessionStore` maps JWT IDs (`jti`, UUID strings) to `SessionData` and must support efficient bulk revocation per user.

```java
public interface SessionStore {
    void                  store(String jti, SessionData sessionData);
    Optional<SessionData> load(String jti);
    void                  revoke(String jti);
    void                  revokeByCredentialIdentifier(String credentialIdentifierBase64);
}
```

`revokeByCredentialIdentifier` is called when a user deletes their credential record.
Implement it efficiently: for small deployments a full scan is acceptable; for production use a secondary index keyed by user (e.g., a Redis Set of JTIs per user, or a `credentialId` column with an index in SQL).

Session records are short-lived (default TTL 3600 seconds), so the table or key-space stays small under normal load.

---

## Generating and managing key material

Generate all secrets with:

```bash
openssl rand -hex 32
```

| Secret             | Config field       | Size     | Purpose                                                          |
|--------------------|--------------------|----------|------------------------------------------------------------------|
| Server AKE seed    | `serverKeySeedHex` | 32 bytes | Deterministically derives the server's long-term OPAQUE key pair |
| OPRF seed          | `oprfSeedHex`      | 32 bytes | Deterministically derives the per-user OPRF evaluation key       |
| OPRF master key    | `oprfMasterKeyHex` | 32 bytes | Evaluation key for the standalone `/oprf` endpoint               |
| JWT signing secret | `jwtSecretHex`     | 32 bytes | HMAC-SHA256 signing key for session tokens                       |

All four must be set for a stable production deployment.  Omitting any one causes either `IllegalStateException` on startup (seed pair) or non-deterministic output across restarts (OPRF master key, JWT secret).

**Never commit secrets to source control.** Use one of the patterns below to inject
them at runtime.

### Injecting secrets from environment variables

Both Spring Boot and Dropwizard support environment variable substitution in their
config files natively. This is the simplest approach and works with any secret
management system that can set environment variables (Docker, Kubernetes, systemd,
CI/CD pipelines).

**Spring Boot (`application.yml`):**

```yaml
hofmann:
  server-key-seed-hex: ${SERVER_KEY_SEED_HEX}
  oprf-seed-hex: ${OPRF_SEED_HEX}
  oprf-master-key-hex: ${OPRF_MASTER_KEY_HEX}
  jwt-secret-hex: ${JWT_SECRET_HEX}
```

**Dropwizard (`config.yml`):**

Dropwizard uses the `${ENV_VAR}` syntax with the
[EnvironmentVariableSubstitutor](https://www.dropwizard.io/en/latest/manual/core.html#environment-variables):

```yaml
serverKeySeedHex: ${SERVER_KEY_SEED_HEX}
oprfSeedHex: ${OPRF_SEED_HEX}
oprfMasterKeyHex: ${OPRF_MASTER_KEY_HEX}
jwtSecretHex: ${JWT_SECRET_HEX}
```

**Docker / Docker Compose:**

```yaml
services:
  app:
    environment:
      SERVER_KEY_SEED_HEX: ${SERVER_KEY_SEED_HEX}
      OPRF_SEED_HEX: ${OPRF_SEED_HEX}
      OPRF_MASTER_KEY_HEX: ${OPRF_MASTER_KEY_HEX}
      JWT_SECRET_HEX: ${JWT_SECRET_HEX}
```

Populate from a `.env` file (not committed), a CI/CD secret store, or a secrets
manager sidecar.

**Kubernetes:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hofmann-secrets
type: Opaque
stringData:
  SERVER_KEY_SEED_HEX: "<value>"
  OPRF_SEED_HEX: "<value>"
  OPRF_MASTER_KEY_HEX: "<value>"
  JWT_SECRET_HEX: "<value>"
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - secretRef:
                name: hofmann-secrets
```

For managed secret stores (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager),
use your platform's sidecar or init container to populate environment variables before
the application starts. The Hofmann library itself does not integrate with any specific
secrets manager — it reads hex strings from configuration, and the injection mechanism
is an infrastructure concern.

### Credential identifier

The credential identifier names the user inside your `CredentialStore`.  Choose a value that is:

- **Stable** — never changes for a given user (changing it orphans the credential record)
- **Canonical** — always the same bytes for the same user (e.g., lower-case before encoding)
- **Globally unique** within your deployment

Common choices:

```java
// Lower-cased email address
byte[] credId = email.toLowerCase(Locale.ROOT).getBytes(UTF_8);

// Binary UUID (compact)
UUID uuid = UUID.fromString(userId);
ByteBuffer buf = ByteBuffer.allocate(16);
buf.putLong(uuid.getMostSignificantBits());
buf.putLong(uuid.getLeastSignificantBits());
byte[] credId = buf.array();
```

The identifier is never transmitted in plaintext — it is hashed into the OPRF evaluation — but you must store the mapping between it and the user record in your own database so you can look up the credential during authentication.

### JWT key rotation

JWT signing keys can be rotated without invalidating in-flight sessions by using the
`jwtPreviousSecretHex` field.  During rotation, tokens signed with the previous key are
still accepted for verification while all new tokens are signed with the current key.

**Step-by-step rotation:**

1. Generate a new secret:

   ```bash
   NEW_JWT_SECRET=$(openssl rand -hex 32)
   ```

2. Deploy with the new secret as `jwtSecretHex` and the old secret as `jwtPreviousSecretHex`:

   **Spring Boot (`application.yml`):**

   ```yaml
   hofmann:
     jwt-secret-hex: ${NEW_JWT_SECRET_HEX}
     jwt-previous-secret-hex: ${OLD_JWT_SECRET_HEX}
   ```

   **Dropwizard (`config.yml`):**

   ```yaml
   jwtSecretHex: ${NEW_JWT_SECRET_HEX}
   jwtPreviousSecretHex: ${OLD_JWT_SECRET_HEX}
   ```

3. After one TTL period (default 1 hour), all tokens signed with the old key have expired.
   Remove `jwtPreviousSecretHex` on the next deploy:

   ```yaml
   hofmann:
     jwt-secret-hex: ${NEW_JWT_SECRET_HEX}
     jwt-previous-secret-hex: ""
   ```

**Dynamic rotation (without restart):**

For systems that need to rotate keys without redeploying, provide a custom
`Supplier<JwtKeyDetail>` that returns the current and previous keys from your secrets
manager.  The supplier is called on every sign and verify operation, so key changes
take effect immediately.

**Spring Boot:**

```java
@Bean
public Supplier<JwtKeyDetail> jwtKeyDetailSupplier(MySecretsManager secrets) {
    return () -> new JwtKeyDetail(
        secrets.currentJwtKey(),
        secrets.previousJwtKey());  // null when no rotation in progress
}
```

**Dropwizard:**

```java
bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore, null)
    .withJwtKeyDetailSupplier(() -> new JwtKeyDetail(
        secrets.currentJwtKey(),
        secrets.previousJwtKey())));
```

**Custom / bare framework:**

```java
Supplier<JwtKeyDetail> supplier = () -> new JwtKeyDetail(
    secrets.currentJwtKey(),
    secrets.previousJwtKey());
JwtManager jwt = new JwtManager(supplier, "my-app", 3600L, sessionStore);
```

When a custom `Supplier<JwtKeyDetail>` is provided, the `jwtSecretHex` and
`jwtPreviousSecretHex` configuration fields are ignored.

### OPRF key rotation (standalone endpoint)

The `Supplier<ServerProcessorDetail>` pattern allows hot key rotation without a restart:

```java
public class KeyRotationService {
    private volatile ServerProcessorDetail current;

    public ServerProcessorDetail current() { return current; }

    // Called by your key management system when a new key is active
    public void rotate(BigInteger newKey, String newKeyId) {
        current = new ServerProcessorDetail(newKey, newKeyId);
    }
}

OprfServerManager oprfManager = new OprfServerManager(
    OprfCipherSuite.P256_SHA256,
    keyRotationService::current);
```

The `processorIdentifier` string (e.g., `"key-v2"`) is returned in every `/oprf` response so callers can track which key version produced a given output.  Keep previous key versions available until all in-flight derived values have been re-derived under the new key.

### OPAQUE key rotation

Every OPAQUE registration record is cryptographically bound to the server's `oprfSeed` and
`serverPrivateKey` that were active at registration time.  Simply replacing `serverKeySeedHex`
or `oprfSeedHex` would silently invalidate all existing registrations.

To rotate safely, keep old keys available for authentication while new registrations use the
new keys.  Clients automatically re-register via the change-password flow when they see the
`keyRotationRequired` flag in the auth response.

**Step-by-step rotation:**

1. Generate new seeds:

   ```bash
   NEW_SERVER_KEY_SEED=$(openssl rand -hex 32)
   NEW_OPRF_SEED=$(openssl rand -hex 32)
   ```

2. Deploy with new seeds as current and old seeds as previous:

   **Spring Boot (`application.yml`):**

   ```yaml
   hofmann:
     server-key-seed-hex: ${NEW_SERVER_KEY_SEED_HEX}
     oprf-seed-hex: ${NEW_OPRF_SEED_HEX}
     previous-server-key-seed-hex: ${OLD_SERVER_KEY_SEED_HEX}
     previous-oprf-seed-hex: ${OLD_OPRF_SEED_HEX}
   ```

   **Dropwizard (`config.yml`):**

   ```yaml
   serverKeySeedHex: ${NEW_SERVER_KEY_SEED_HEX}
   oprfSeedHex: ${NEW_OPRF_SEED_HEX}
   previousServerKeySeedHex: ${OLD_SERVER_KEY_SEED_HEX}
   previousOprfSeedHex: ${OLD_OPRF_SEED_HEX}
   ```

3. Users log in gradually.  Each login authenticates with the old keys, then the Java and
   TypeScript clients automatically re-register the credential under the new keys (via the
   existing change-password flow).  This is transparent to the user.

4. Monitor migration progress by querying your `CredentialStore` for remaining version 0
   records.

5. After all credentials are migrated (or after a deadline), remove the previous seeds:

   ```yaml
   hofmann:
     server-key-seed-hex: ${NEW_SERVER_KEY_SEED_HEX}
     oprf-seed-hex: ${NEW_OPRF_SEED_HEX}
     previous-server-key-seed-hex: ""
     previous-oprf-seed-hex: ""
   ```

   Users who never logged in during the rotation window will need to re-register via the
   account recovery flow.

**Versioned credential storage:**

The `CredentialStore` interface has default `store(id, record, keyVersion)` and
`loadVersioned(id)` methods.  The defaults delegate to the unversioned methods with
version 0, so existing implementations continue to work.  For production, override these
to persist a `key_version` column:

```java
@Override
public void store(byte[] id, RegistrationRecord record, int keyVersion) {
    jdbcTemplate.update(
        "INSERT INTO credentials(id, record_bytes, key_version) VALUES (?, ?, ?) " +
        "ON CONFLICT(id) DO UPDATE SET record_bytes = EXCLUDED.record_bytes, " +
        "key_version = EXCLUDED.key_version",
        id, record.serialize(), keyVersion);
}

@Override
public Optional<VersionedCredential> loadVersioned(byte[] id) {
    List<VersionedCredential> rows = jdbcTemplate.query(
        "SELECT record_bytes, key_version FROM credentials WHERE id = ?",
        (rs, n) -> new VersionedCredential(
            rs.getInt("key_version"),
            RegistrationRecord.deserialize(rs.getBytes("record_bytes"))),
        id);
    return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
}
```

**Dynamic rotation (without restart):**

Provide a custom `Supplier<OpaqueServerKeyDetail>` that returns the current and previous
servers from your key management system:

**Spring Boot:**

```java
@Bean
public Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier(KeyVaultService vault) {
    return () -> vault.currentOpaqueKeyDetail();
}
```

**Dropwizard:**

```java
bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore, null)
    .withOpaqueServerKeyDetailSupplier(() -> vault.currentOpaqueKeyDetail()));
```

When a custom supplier is provided, the seed configuration fields are ignored.

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

Clients connecting to the testserver can use `HofmannOpaqueClientManager(accessor)` without
any manual config — the manager fetches the cipher suite, context, and Argon2id parameters
automatically from `GET /opaque/config` on first use.  If you are constructing
`OpaqueClientConfig` directly (e.g. for a CLI override), use `withArgon2id(...)` — not
`forTesting(...)`, which uses the identity KSF and will fail against a server with Argon2
enabled.
