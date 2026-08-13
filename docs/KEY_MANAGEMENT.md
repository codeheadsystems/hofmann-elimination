# Key Management

Generating the four secrets, injecting them at runtime, choosing a credential identifier, and the
rotation runbooks for JWT, OPRF and OPAQUE keys.

> [Server configuration](../USAGE.md) · [Client configuration](CLIENT_CONFIG.md) · [Framework integration](INTEGRATION.md) · **Key management** · [Doc map](README.md)

---

## Generating key material

Generate all secrets with:

```bash
openssl rand -hex 32
```

| Secret             | Config field        | Size     | Purpose                                                          |
|--------------------|---------------------|----------|------------------------------------------------------------------|
| Server AKE seed    | `serverKeySeedHex`  | 32 bytes | Deterministically derives the server's long-term OPAQUE key pair |
| OPRF seed          | `oprfSeedHex`       | 32 bytes | Deterministically derives the per-user OPRF evaluation key       |
| OPRF master key    | `oprfMasterKeyHex`  | 32 bytes | Evaluation key for the standalone `/oprf` endpoint               |
| JWT signing secret | `jwtSecretHex`      | 32 bytes | HMAC-SHA256 signing key for session tokens                       |
| VOPRF master key   | `voprfMasterKeyHex` | 32 bytes | Evaluation key for `/oprf/verifiable`.  Optional — empty disables the mode |
| POPRF master key   | `poprfMasterKeyHex` | 32 bytes | Evaluation key for `/oprf/partially-oblivious`.  Optional — empty disables the mode |

The first four must be set for a stable production deployment.  Omitting any one causes either `IllegalStateException` on startup (seed pair) or non-deterministic output across restarts (OPRF master key, JWT secret).

The two verifiable-mode keys are optional; leaving them empty disables the mode and the endpoint answers `404`.  If you do enable them, **they must be two different secrets.**  RFC 9497 puts the mode byte in every domain-separation tag, so one secret serving two modes computes two different functions — but the §7.2.3 static Diffie-Hellman budget is per-key, and POPRF exposes an inversion oracle where the other modes expose a multiplication one.  There is deliberately no ephemeral fallback for either: the value of a verifiable mode is that clients pin the public key, and a key regenerated on restart would silently invalidate every pinned copy.

**Never commit secrets to source control.** Use one of the patterns below to inject
them at runtime.

---

## Injecting secrets from environment variables

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

---

## Credential identifier

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

---

## JWT key rotation

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

---

## OPRF key rotation (standalone endpoint)

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

---

## Publishing the verifiable-mode public keys

Enabling VOPRF or POPRF adds an operational step that base mode does not have: **the server's
public key has to reach clients out of band.**

A verifiable mode lets a client check that the server evaluated with the key it publicly
committed to.  That check is worth nothing if the key arrives from the same server, over the same
connection, as the proof it authenticates — a server able to choose both can produce a verifying
pair for any key it likes, and RFC 9497 §7.3 notes it can do so per client, partitioning users
into individually identifiable buckets while every proof still verifies.

So publish it through whatever channel already carries your other trust anchors: checked into the
client's configuration, shipped in a signed bundle, distributed by your configuration management.
Not by having the client call `/oprf/config`.

Read the key off a configured server with:

```bash
curl -s https://your-server.example.com/oprf/config | jq -r '.modes[] | "\(.mode) \(.publicKeyHex)"'
```

`/oprf/config` advertises it so that clients can **cross-check** a key they already pinned and
fail loudly on a mismatch.  That is a diagnostic, not a distribution channel: the response is
unauthenticated, so the check can only refuse, never accept.  See
[Client configuration](CLIENT_CONFIG.md).

### Rotating a verifiable-mode key

**Rotation is not transparent, and the order matters.** Every client holding the old pin will
refuse the new key at the cross-check, and would fail proof verification even without it.

1. Derive the new public key and distribute it to clients.
2. Wait for the fleet to pick it up.
3. Switch the server's `voprfMasterKeyHex` / `poprfMasterKeyHex`.

Reversing steps 1 and 3 is an outage for every client that has not been updated.  If you need
overlap, run the old and new keys as two deployments behind separate `processIdentifier` values
and migrate clients across, rather than swapping under a live fleet.

---

## OPAQUE key rotation

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
