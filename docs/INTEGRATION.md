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

`CredentialStore` persists one `RegistrationRecord` per user.  The key is a `credentialIdentifier` byte array — the user's canonical, stable identifier (see [Credential identifier](KEY_MANAGEMENT.md#credential-identifier)).

The interface has six methods.  Three are abstract; three have defaults that exist so an
implementation written against an earlier version keeps compiling.  **Two of those defaults are
not safe in production**, and because they compile, nothing tells you when you have kept them:

```java
public interface CredentialStore {
    // Abstract — you must implement these.
    void                         store(byte[] credentialIdentifier, RegistrationRecord record);
    Optional<RegistrationRecord> load(byte[] credentialIdentifier);
    void                         delete(byte[] credentialIdentifier);

    // Defaulted — override all three for production.
    default void store(byte[] credentialIdentifier, RegistrationRecord record, int keyVersion);
    default boolean storeIfAbsent(byte[] credentialIdentifier, RegistrationRecord record,
                                  int keyVersion);
    default Optional<VersionedCredential> loadVersioned(byte[] credentialIdentifier);
}
```

All six methods must be thread-safe.  Two contracts are load-bearing:

**`store` must be an upsert.**  A single operation that leaves either the old record or the new
one visible, never neither.  The server replaces a record during recovery and password change and
relies on there being no window in which the account does not exist.

**`storeIfAbsent` must be atomic, and its default is not.**  Registration finish is
unauthenticated: without a guard, anyone who knows a victim's credential identifier can
re-register it with their own password and take over the account.  Expressing that guard as
`load(...).isPresent()` followed by `store(...)` is a check-then-act — two concurrent finishes for
the same identifier can both observe "absent" and both write.  The store is the only place that
can make the check and the write one operation, which is why the primitive lives here.  The
default implementation performs exactly the check-then-act it exists to prevent.

A JDBC implementation.  Note that it overrides all six methods, and that `key_version` is what
makes [OPAQUE key rotation](KEY_MANAGEMENT.md#opaque-key-rotation) work — keep the default
`loadVersioned` and every credential reports version 0 forever:

```java
public class JdbcCredentialStore implements CredentialStore {

    // Schema: id BYTEA PRIMARY KEY, record_bytes BYTEA NOT NULL, key_version INT NOT NULL

    @Override
    public void store(byte[] id, RegistrationRecord record) {
        store(id, record, 0);
    }

    @Override
    public void store(byte[] id, RegistrationRecord record, int keyVersion) {
        jdbcTemplate.update(
            "INSERT INTO credentials(id, record_bytes, key_version) VALUES (?, ?, ?) " +
            "ON CONFLICT(id) DO UPDATE SET record_bytes = EXCLUDED.record_bytes, " +
            "key_version = EXCLUDED.key_version",
            id, record.serialize(), keyVersion);
    }

    @Override
    public boolean storeIfAbsent(byte[] id, RegistrationRecord record, int keyVersion) {
        // DO NOTHING, not DO UPDATE. The check and the write are one statement, and the row
        // count tells us which of the two happened. A racing second caller gets false.
        return jdbcTemplate.update(
            "INSERT INTO credentials(id, record_bytes, key_version) VALUES (?, ?, ?) " +
            "ON CONFLICT(id) DO NOTHING",
            id, record.serialize(), keyVersion) == 1;
    }

    @Override
    public Optional<RegistrationRecord> load(byte[] id) {
        // query + isEmpty, not queryForObject. The idiomatic queryForObject throws
        // EmptyResultDataAccessException for an unknown user, which the adapters map to 500
        // while a wrong password returns 401 — an enumeration oracle in the error code.
        List<byte[]> rows = jdbcTemplate.query(
            "SELECT record_bytes FROM credentials WHERE id = ?",
            (rs, n) -> rs.getBytes(1), id);
        return rows.isEmpty()
            ? Optional.empty()
            : Optional.of(RegistrationRecord.deserialize(rows.get(0)));
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

    @Override
    public void delete(byte[] id) {
        jdbcTemplate.update("DELETE FROM credentials WHERE id = ?", id);
    }
}
```

The atomic conditional write is `INSERT ... ON CONFLICT DO NOTHING` on PostgreSQL and SQLite,
`INSERT IGNORE` on MySQL, and a conditional put on a key-value store — DynamoDB's
`attribute_not_exists(id)` condition expression, or Redis `SET NX`.  In every case
`storeIfAbsent` returns whether *this* caller performed the write.

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
