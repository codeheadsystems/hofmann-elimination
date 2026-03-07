# Migrating to OPAQUE

This guide covers how to migrate an existing application that uses traditional password
authentication (bcrypt, scrypt, Argon2id hashing) to OPAQUE via the Hofmann Elimination
library.

OPAQUE cannot verify legacy password hashes. There is no way to convert a bcrypt hash
into an OPAQUE credential record without the user's plaintext password. Migration
therefore requires each user to re-register through the OPAQUE protocol, which means
the user must supply their password one final time.

This guide presents three strategies for handling that transition, from simplest to most
seamless.

---

## Before you start

### 1. Deploy the OPAQUE server alongside your existing auth

Add the Hofmann starter to your application. Both auth systems run in parallel during
migration. No existing functionality changes yet.

**Spring Boot:**

```groovy
dependencies {
    implementation 'com.codeheadsystems:hofmann-springboot:<version>'
}
```

**Dropwizard:**

```java
bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore, null));
```

See [USAGE.md](USAGE.md) for full configuration, key material generation, and
`CredentialStore` / `SessionStore` implementation.

### 2. Deploy the OPAQUE client

Add the TypeScript or Java client to your frontend or client application.

**TypeScript (browser/Node):**

```bash
npm install @codeheadsystems/hofmann-typescript
```

**Java:**

```groovy
dependencies {
    implementation 'com.codeheadsystems:hofmann-client:<version>'
}
```

Both clients auto-configure themselves from the server's `/opaque/config` endpoint.

### 3. Implement a dual credential store

Your `CredentialStore` implementation needs to coexist with your legacy password table.
The simplest approach is a separate table:

```sql
CREATE TABLE opaque_credentials (
    credential_id BYTEA PRIMARY KEY,
    record_bytes  BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Your existing `users` table keeps its `password_hash` column until migration is complete.

---

## Strategy 1: Forced re-registration

The simplest approach. Pick a cutover date, require all users to set a new password
through OPAQUE, and remove legacy auth.

### How it works

1. Deploy OPAQUE endpoints alongside existing auth.
2. On the cutover date, disable legacy login.
3. Direct all users to a "Set new password" flow that calls the OPAQUE registration
   endpoints. Users enter their current password (verified against the legacy hash
   one last time) and a new password (registered via OPAQUE).
4. Once registered, users authenticate exclusively via OPAQUE.
5. After a grace period, delete the legacy `password_hash` column.

### When to use this

- Internal applications with a small user base
- Applications where you can coordinate a maintenance window
- Situations where you want a clean cutover with no dual-auth complexity

### Drawbacks

- Users who miss the window are locked out until they go through account recovery
- Requires a grace period and communication plan

---

## Strategy 2: Opportunistic migration on login

Users are migrated transparently the next time they log in. Both auth systems run in
parallel until the legacy population drains to zero.

### How it works

1. Deploy OPAQUE endpoints alongside existing auth.
2. On every login attempt, check whether the user has an OPAQUE credential record.
3. **If yes:** authenticate via OPAQUE. Ignore the legacy hash.
4. **If no:** authenticate via the legacy hash. If successful, immediately register
   the user via OPAQUE using the password they just supplied. The user does not need
   to do anything differently.
5. Once the OPAQUE registration succeeds, the user's subsequent logins use OPAQUE.
6. Monitor the count of users without OPAQUE credentials. When it reaches zero (or
   an acceptable threshold), remove legacy auth.

### Server-side pseudocode

```java
public AuthResult login(String username, String password) {
    byte[] credentialId = username.toLowerCase().getBytes(UTF_8);

    // Try OPAQUE first
    if (opaqueCredentialStore.load(credentialId).isPresent()) {
        return opaqueAuthenticate(credentialId, password);
    }

    // Fall back to legacy
    User user = userRepository.findByUsername(username);
    if (user == null || !legacyHashVerify(password, user.getPasswordHash())) {
        throw new SecurityException("Authentication failed");
    }

    // Legacy succeeded — register via OPAQUE in the background
    opaqueRegister(credentialId, password);

    // Issue session using legacy flow this one last time
    return legacySession(user);
}
```

### Client-side flow (TypeScript example)

For applications where OPAQUE registration and authentication happen on the client:

```typescript
async function login(username: string, password: string): Promise<string> {
    const opaqueClient = await OpaqueHttpClient.create(serverUrl);

    try {
        // Try OPAQUE authentication first
        return await opaqueClient.authenticate(username, password);
    } catch (e) {
        // OPAQUE failed — try legacy login
        const legacyToken = await legacyLogin(username, password);

        // Legacy succeeded — register via OPAQUE for next time
        await opaqueClient.register(username, password);

        return legacyToken;
    }
}
```

### When to use this

- Consumer-facing applications with large user bases
- Situations where you cannot force users through a re-registration flow
- When you want zero disruption to the user experience

### Drawbacks

- Dual auth code runs until the last user logs in
- Users who never log in again are never migrated (combine with Strategy 1 for a
  long-tail cutover date)
- The legacy password is briefly available in memory during the migration login

### Monitoring

Track migration progress with a simple query:

```sql
-- Users not yet migrated
SELECT count(*) FROM users u
WHERE u.password_hash IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM opaque_credentials oc
    WHERE oc.credential_id = u.credential_id
  );
```

---

## Strategy 3: Transparent migration with password change requirement

A hybrid approach: opportunistic migration for active users, plus a forced password
change for dormant accounts after a deadline.

### How it works

1. Deploy OPAQUE alongside legacy auth (same as Strategy 2).
2. Migrate active users opportunistically on login (same as Strategy 2).
3. Set a deadline (e.g., 90 days). After the deadline, mark all remaining
   un-migrated accounts as requiring a password reset.
4. When these users next attempt to log in, direct them through account recovery
   (email/SMS verification) followed by OPAQUE registration.
5. After the deadline, remove legacy auth code.

### Timeline example

| Week | Action |
|------|--------|
| 0    | Deploy OPAQUE endpoints. Begin opportunistic migration on login. |
| 1-2  | Monitor migration rate. Send email to users who haven't logged in recently. |
| 8    | Send final notice to remaining un-migrated users. |
| 12   | Disable legacy auth. Un-migrated users must reset their password. |
| 14   | Drop `password_hash` column. Remove legacy auth code. |

### When to use this

- Most production applications — balances user experience with a firm cutover deadline
- Regulated environments where you need an audit trail of the migration

---

## Credential identifier mapping

OPAQUE uses a `credentialIdentifier` (an opaque byte array) as the key for each
registration record. You need a consistent mapping from your existing user identity
to this byte array.

Common patterns:

```java
// Lower-cased email — simple and human-readable
byte[] credentialId = email.toLowerCase(Locale.ROOT).getBytes(UTF_8);

// UUID — compact and stable even if email changes
UUID userId = user.getId();
ByteBuffer buf = ByteBuffer.allocate(16);
buf.putLong(userId.getMostSignificantBits());
buf.putLong(userId.getLeastSignificantBits());
byte[] credentialId = buf.array();
```

Choose a value that is **stable** (never changes for a given user), **canonical**
(always produces the same bytes), and **unique** within your deployment. See the
[credential identifier section](USAGE.md#credential-identifier) in USAGE.md.

If you use email addresses and your application allows email changes, use an internal
user ID instead. Changing the credential identifier after registration orphans the
OPAQUE credential record.

---

## Database schema changes

### During migration (both systems active)

Your existing `users` table keeps its `password_hash` column. Add a new table for
OPAQUE credentials and optionally a migration status column:

```sql
-- New table for OPAQUE credential records
CREATE TABLE opaque_credentials (
    credential_id BYTEA PRIMARY KEY,
    record_bytes  BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Optional: track migration status on the user record
ALTER TABLE users ADD COLUMN opaque_migrated BOOLEAN NOT NULL DEFAULT false;
```

### After migration is complete

```sql
ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users DROP COLUMN opaque_migrated;
```

---

## Argon2id parameter selection

OPAQUE uses Argon2id as a key stretching function (KSF) on the **client side**. The
parameters must be chosen with client hardware in mind, not server hardware.

| Parameter | Recommended | Notes |
|-----------|-------------|-------|
| `argon2MemoryKib` | 65536 (64 MiB) | Lower for mobile clients. 19456 (19 MiB) is a common mobile target. |
| `argon2Iterations` | 3 | Higher values increase CPU time linearly. |
| `argon2Parallelism` | 1 | Must be 1 for single-threaded browser environments (hash-wasm limitation). |

Test on your lowest-spec target client. OPAQUE authentication requires two Argon2id
evaluations (registration and each login), so the latency impact is doubled compared
to server-side Argon2id.

**Changing Argon2id parameters after users have registered invalidates all existing
OPAQUE registrations.** Plan parameter upgrades as a full re-registration migration.

---

## Security considerations during migration

### Legacy password in memory

During opportunistic migration (Strategy 2), the user's plaintext password is
briefly held in server memory to perform both the legacy hash verification and
the OPAQUE registration. This is the same exposure as a normal legacy login.
After the OPAQUE registration completes, the password is no longer needed.

### Dual auth attack surface

While both authentication systems are active, an attacker who compromises the
legacy password hash can still authenticate via the legacy path. The migration
period should be as short as practical. Monitor the migration rate and set a
firm deadline for removing legacy auth.

### Rollback plan

If you need to roll back during migration:

1. OPAQUE endpoints can be disabled without affecting legacy auth.
2. Users who were already migrated can be directed through a password reset flow
   to re-establish a legacy hash.
3. The `opaque_credentials` table can be dropped without affecting the `users` table.

Keep the legacy auth code deployed (but disabled for migrated users) until you are
confident the migration is complete and stable.

### Token compatibility

The Hofmann server issues JWTs on successful OPAQUE authentication. If your
application already uses JWTs, configure the Hofmann JWT issuer and secret to match
your existing token infrastructure, or have your application accept tokens from
both issuers during the migration period.

```yaml
# Match your existing JWT configuration
hofmann:
  jwt-secret-hex: <your-existing-jwt-secret-as-hex>
  jwt-issuer: your-app-name
  jwt-ttl-seconds: 3600
```

---

## Checklist

- [ ] Generate and securely store OPAQUE key material (`serverKeySeedHex`, `oprfSeedHex`, `oprfMasterKeyHex`, `jwtSecretHex`) — see [USAGE.md](USAGE.md#generating-and-managing-key-material)
- [ ] Implement `CredentialStore` backed by your database
- [ ] Implement `SessionStore` backed by your session infrastructure (Redis, database, etc.)
- [ ] Deploy OPAQUE endpoints alongside legacy auth
- [ ] Deploy updated client with OPAQUE support
- [ ] Implement dual-auth login flow (Strategy 1, 2, or 3)
- [ ] Add monitoring for migration progress
- [ ] Communicate timeline to users (if using forced migration)
- [ ] Set a deadline for removing legacy auth
- [ ] After deadline: disable legacy login, remove `password_hash` column
- [ ] Remove dual-auth code paths
