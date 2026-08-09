# Framework Integration

Wiring Hofmann into Dropwizard, Spring Boot, or your own HTTP layer, and implementing the two
persistence interfaces it requires.

> [Server configuration](../USAGE.md) · [Client configuration](CLIENT_CONFIG.md) · **Framework integration** · [Key management](KEY_MANAGEMENT.md) · [Doc map](README.md)

Configuration field names and defaults are in the
[server configuration guide](../USAGE.md#configuration-reference).

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
    implementation 'com.codeheadsystems:hofmann-springboot:<version>'
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

Configure in `application.yml` using the same field names as the [Dropwizard YAML table](../USAGE.md#configuration-reference), prefixed with `hofmann.`:

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
    implementation 'com.codeheadsystems:hofmann-server:<version>'
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

`CredentialStore` persists one `RegistrationRecord` per user.  The key is a `credentialIdentifier` byte array — the user's canonical, stable identifier (see [Credential identifier](KEY_MANAGEMENT.md#credential-identifier) below).

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
