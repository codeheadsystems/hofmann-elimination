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
| `opaqueCipherSuite` | `P256_SHA256`       | No                      | Cipher suite for OPAQUE. Accepted values: `P256_SHA256`, `P384_SHA384`, `P521_SHA512`. Must match the client exactly.                                                                                                                |
| `context`           | `hofmann-opaque-v1` | **Yes**                 | Application context string bound into the OPAQUE preamble. Must be unique per deployment. Shared between server and client out-of-band.                                                                                              |
| `serverKeySeedHex`  | `""` (random)       | **Yes**                 | Hex-encoded 32-byte seed that deterministically derives the server's long-term AKE key pair. Generate with `openssl rand -hex 32`.                                                                                                   |
| `oprfSeedHex`       | `""` (random)       | **Yes**                 | Hex-encoded 32-byte seed that deterministically derives per-credential OPRF keys. Generate with `openssl rand -hex 32`. Must be set together with `serverKeySeedHex` — providing only one throws `IllegalStateException` on startup. |
| `argon2MemoryKib`   | `65536`             | **Yes**                 | Argon2id memory cost in kibibytes. Set to `0` to disable Argon2 (identity KSF — for testing only). See [Argon2id consistency](#argon2id-consistency-between-server-and-client) below.                                                |
| `argon2Iterations`  | `3`                 | **Yes**                 | Argon2id iteration count. Ignored when `argon2MemoryKib` is `0`.                                                                                                                                                                     |
| `argon2Parallelism` | `1`                 | **Yes**                 | Argon2id parallelism. Ignored when `argon2MemoryKib` is `0`.                                                                                                                                                                         |

### OPRF (standalone endpoint)

| Field              | Default           | Required for production | Description                                                                                                                                                                                                                                           |
|--------------------|-------------------|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `oprfCipherSuite`  | `P256_SHA256`     | No                      | Cipher suite for the standalone `/oprf` endpoint. Independent of `opaqueCipherSuite`.                                                                                                                                                                 |
| `oprfMasterKeyHex` | `""` (random)     | **Yes**                 | Hex-encoded scalar used as the OPRF master key. Must be a valid non-zero scalar in the chosen curve group. Generate with `openssl rand -hex 32`. An empty value generates a random key on each startup, making OPRF outputs unstable across restarts. |
| `oprfProcessorId`  | `hofmann-oprf-v1` | No                      | Human-readable identifier returned in every OPRF response. Useful for tracing which key produced a given output during key rotation.                                                                                                                  |

### JWT

| Field           | Default       | Required for production | Description                                                                                                                                                                              |
|-----------------|---------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jwtSecretHex`  | `""` (random) | **Yes**                 | Hex-encoded 32-byte HMAC-SHA256 signing secret. Generate with `openssl rand -hex 32`. An empty value generates a random secret on each startup, invalidating all tokens after a restart. |
| `jwtTtlSeconds` | `3600`        | No                      | Token time-to-live in seconds.                                                                                                                                                           |
| `jwtIssuer`     | `hofmann`     | No                      | Value placed in the JWT `iss` claim.                                                                                                                                                     |

### Security

| Field                 | Default | Required for production | Description                                                                                                                                                                                                      |
|-----------------------|---------|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `maxRequestBodyBytes` | `65536` | No                      | Requests with a `Content-Length` header exceeding this value are rejected with HTTP 413 before the body is read. The largest OPAQUE message is well under 64 KiB; raise this only if you have a specific reason. |

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

| Server config field | Matching client parameter | `OpaqueClientConfig` factory          |
|---------------------|---------------------------|---------------------------------------|
| `opaqueCipherSuite` | cipher suite name         | `withArgon2id(suiteName, ...)`        |
| `context`           | context string            | `withArgon2id(..., context, ...)`     |
| `argon2MemoryKib`   | `argon2MemoryKib`         | `withArgon2id(..., memory, ...)`      |
| `argon2Iterations`  | `argon2Iterations`        | `withArgon2id(..., iterations, ...)`  |
| `argon2Parallelism` | `argon2Parallelism`       | `withArgon2id(..., parallelism, ...)` |

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

## Spring Boot integration

Add the autoconfiguration dependency:

```groovy
dependencies {
    implementation 'com.codeheadsystems.hofmann:hofmann-springboot:<version>'
}
```

Autoconfiguration activates automatically.  Every bean is `@ConditionalOnMissingBean` — override any by declaring your own `@Bean`:

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

// Key rotation via dynamic supplier
@Bean
public Supplier<ServerProcessorDetail> serverProcessorDetailSupplier(KeyRotationService svc) {
    return () -> new ServerProcessorDetail(svc.currentKey(), svc.currentKeyId());
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

// 5. Build the JWT manager
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

OPAQUE server keys cannot be rotated transparently.  Every registered credential is cryptographically bound to the specific server AKE key pair and OPRF seed that were active at registration time.  Rotating `serverKeySeedHex` or `oprfSeedHex` silently invalidates all existing registrations — the authentication MAC check will fail as if the user supplied a wrong password.

Plan for key rotation by:

1. Versioning credential records in your `CredentialStore` (e.g., a `key_version` column).
2. On login, detecting a version mismatch and prompting the user to re-register.
3. Never rotating without notifying affected users in advance.

---

## Endpoints registered by the bundle

| Method   | Path                          | Auth required | Description                                                 |
|----------|-------------------------------|---------------|-------------------------------------------------------------|
| `POST`   | `/opaque/registration/start`  | No            | Begin OPAQUE registration (returns blinded OPRF evaluation) |
| `POST`   | `/opaque/registration/finish` | No            | Complete registration (stores credential record)            |
| `DELETE` | `/opaque/registration`        | Bearer token  | Delete a credential record                                  |
| `POST`   | `/opaque/auth/start`          | No            | Begin OPAQUE authentication (KE1 → KE2)                     |
| `POST`   | `/opaque/auth/finish`         | No            | Complete authentication (KE3 → JWT)                         |
| `POST`   | `/oprf`                       | No            | Standalone OPRF evaluation                                  |

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
