# Account Recovery for OPAQUE

## Overview

OPAQUE is a password-authenticated key exchange where the server **never sees the password**.
This means there is no "password reset email" in the traditional sense — the server cannot
generate a new password or hash on the user's behalf. Instead, account recovery is
**verified re-registration**: the user proves their identity through an out-of-band mechanism,
then registers a new password using the standard OPAQUE registration protocol.

Recovery is **opt-in**. If you do not configure a `RecoveryChallenger`, the recovery
endpoints return 404 and the OPAQUE protocol operates exactly as before.

## Recovery Flow

```
Client                                Server
  |                                     |
  |--- POST /opaque/recovery/start --->|  (credentialIdentifier)
  |<-- 202 Accepted -------------------|  [server sends challenge via RecoveryChallenger]
  |                                     |
  | [user receives challenge out-of-band|
  |  e.g. email code, SMS OTP, etc.]    |
  |                                     |
  |--- POST /opaque/recovery/verify -->|  (credentialIdentifier + challengeResponse)
  |<-- RecoveryVerifyResponse ----------|  (recoveryToken)
  |                                     |
  | [client uses recoveryToken as       |
  |  Bearer header for re-registration] |
  |                                     |
  |--- POST /registration/start ------>|  (with Authorization: Bearer <recoveryToken>)
  |<-- RegistrationStartResponse -------|
  |                                     |
  |--- POST /registration/finish ----->|  (with Authorization: Bearer <recoveryToken>)
  |<-- 204 No Content ------------------|  [old credential deleted, new one stored]
```

When the registration endpoints receive a valid recovery token:

1. `registrationStart` validates the token matches the credential (without consuming it)
2. `registrationFinish` consumes the token, deletes the old credential, revokes all
   active JWTs for that credential, and stores the new registration record

The OPAQUE cryptographic protocol is identical to a fresh registration — no changes to
`hofmann-rfc`, no new crypto code, no new attack surface.

## Implementing `RecoveryChallenger`

`RecoveryChallenger` is the **only interface you must implement** to enable recovery.
It defines how your application sends and verifies out-of-band identity challenges.

```java
public interface RecoveryChallenger {

    /**
     * Sends an out-of-band challenge to the user identified by credentialIdentifier.
     *
     * This method MUST NOT reveal whether the credential exists. If the
     * credential is unknown, either silently succeed (recommended) or
     * send a generic "if this account exists..." message.
     */
    void sendChallenge(byte[] credentialIdentifier);

    /**
     * Verifies the user's response to a previously sent challenge.
     *
     * @return true if the response is valid
     */
    boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse);
}
```

### Example: Email-Based Recovery

```java
public class EmailRecoveryChallenger implements RecoveryChallenger {

    private final EmailService emailService;
    private final Map<String, TimedCode> pendingCodes = new ConcurrentHashMap<>();

    @Override
    public void sendChallenge(byte[] credentialIdentifier) {
        String email = new String(credentialIdentifier, StandardCharsets.UTF_8);
        String code = generateSecureCode();  // e.g. 6-digit random
        pendingCodes.put(email, new TimedCode(code, Instant.now()));
        emailService.send(email, "Your recovery code", "Code: " + code);
    }

    @Override
    public boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse) {
        String email = new String(credentialIdentifier, StandardCharsets.UTF_8);
        TimedCode stored = pendingCodes.remove(email);
        if (stored == null) return false;
        if (stored.isExpired(Duration.ofMinutes(10))) return false;
        return MessageDigest.isEqual(
            stored.code().getBytes(), challengeResponse.getBytes());
    }
}
```

### Example: TOTP-Based Recovery

```java
public class TotpRecoveryChallenger implements RecoveryChallenger {

    private final TotpSecretStore totpStore;

    @Override
    public void sendChallenge(byte[] credentialIdentifier) {
        // TOTP doesn't need to "send" anything — the user's authenticator
        // app already has the shared secret. This is a no-op.
    }

    @Override
    public boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse) {
        return totpStore.loadSecret(credentialIdentifier)
            .map(secret -> TotpValidator.validate(secret, challengeResponse))
            .orElse(false);
    }
}
```

### Rust

The Rust crate provides the equivalent trait:

```rust
pub trait RecoveryChallenger: Send + Sync {
    fn send_challenge(&self, credential_identifier: &[u8]) -> Result<(), String>;
    fn verify_response(&self, credential_identifier: &[u8], challenge_response: &str) -> bool;
}
```

## Implementing `RecoveryTokenStore` (Optional)

A default `InMemoryRecoveryTokenStore` is provided (10-minute TTL, 10,000 capacity).
For multi-node deployments, implement `RecoveryTokenStore` with a distributed backend.

```java
public interface RecoveryTokenStore {

    /** Stores a recovery token. Throws if the store has reached capacity. */
    void store(String token, String credentialIdentifierBase64);

    /** Retrieves without consuming. Returns empty if not found or expired. */
    Optional<String> peek(String token);

    /** Retrieves and atomically removes (consume-once). Returns empty if not found or expired. */
    Optional<String> remove(String token);

    /** Shuts down background resources (e.g. reaper threads). */
    default void shutdown() {}
}
```

**Production example:** Redis with `SET token credentialId EX 600 NX`.

The Rust crate provides the equivalent trait and in-memory implementation:

```rust
pub trait RecoveryTokenStore: Send + Sync {
    fn store(&self, token: &str, credential_identifier: &str) -> Result<(), String>;
    fn peek(&self, token: &str) -> Option<String>;
    fn remove(&self, token: &str) -> Option<String>;
}
```

## Wiring

### Spring Boot

Define your `RecoveryChallenger` as a Spring bean. The auto-configuration handles the rest:

```java
@Bean
public RecoveryChallenger recoveryChallenger(EmailService emailService) {
    return new EmailRecoveryChallenger(emailService);
}
```

When a `RecoveryChallenger` bean is present, `HofmannAutoConfiguration` automatically creates:
- An `InMemoryRecoveryTokenStore` bean (override with your own `RecoveryTokenStore` bean)
- A recovery rate limiter

If no `RecoveryChallenger` bean is present, recovery endpoints return 404.

### Dropwizard

Use the fluent `withRecovery()` method on `HofmannBundle`:

```java
bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore, null)
    .withRecovery(new EmailRecoveryChallenger(emailService)));
```

For a custom token store:

```java
bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore, null)
    .withRecovery(challenger, new RedisRecoveryTokenStore(redisClient)));
```

Without `withRecovery()`, recovery endpoints return 404.

## Client Usage

### Java Client

The `HofmannOpaqueClientManager` supports recovery via an overloaded `register()` method:

```java
// Normal registration
manager.register(serverId, credentialId, password);

// Recovery re-registration (with token from POST /opaque/recovery/verify)
manager.register(serverId, credentialId, newPassword, recoveryToken);
```

The recovery start and verify steps require direct HTTP calls to the
`/opaque/recovery/start` and `/opaque/recovery/verify` endpoints (see API Reference below).

### TypeScript Client

`OpaqueHttpClient` provides recovery methods:

```typescript
// Step 1: Send challenge
await client.recoveryStart(credentialId);

// Step 2: Verify (returns single-use recovery token)
const recoveryToken = await client.recoveryVerify(credentialId, challengeResponse);

// Step 3: Re-register with recovery token
await client.register(credentialId, newPassword, undefined, undefined, recoveryToken);

// Or use the convenience method (steps 2+3 combined):
await client.recoverAndReRegister(credentialId, challengeResponse, newPassword);
```

## API Reference

### Endpoints

| Method | Path                       | Request Body             | Response                 | Status |
|--------|----------------------------|--------------------------|--------------------------|--------|
| POST   | `/opaque/recovery/start`   | `RecoveryStartRequest`   | —                        | 202    |
| POST   | `/opaque/recovery/verify`  | `RecoveryVerifyRequest`  | `RecoveryVerifyResponse` | 200    |

The existing registration endpoints (`/opaque/registration/start` and
`/opaque/registration/finish`) accept an optional `Authorization: Bearer <recoveryToken>`
header to authorize re-registration.

### `RecoveryStartRequest`

```json
{ "credentialIdentifier": "dXNlckBleGFtcGxlLmNvbQ==" }
```

| Field                  | Type   | Description                          |
|------------------------|--------|--------------------------------------|
| `credentialIdentifier` | string | Base64-encoded credential identifier |

### `RecoveryVerifyRequest`

```json
{
  "credentialIdentifier": "dXNlckBleGFtcGxlLmNvbQ==",
  "challengeResponse": "482901"
}
```

| Field                  | Type   | Description                          |
|------------------------|--------|--------------------------------------|
| `credentialIdentifier` | string | Base64-encoded credential identifier |
| `challengeResponse`    | string | User's response to the challenge     |

### `RecoveryVerifyResponse`

```json
{ "recoveryToken": "a3f8c2d1-7b4e-4f9a-9c6e-2d1f3e4a5b6c" }
```

| Field           | Type   | Description                                  |
|-----------------|--------|----------------------------------------------|
| `recoveryToken` | string | Single-use token authorizing re-registration |

### Error Responses

| Status | Condition                                  |
|--------|--------------------------------------------|
| 202    | Challenge sent (always, even for unknown credentials) |
| 200    | Challenge verified, recovery token returned |
| 400    | Missing or invalid request fields          |
| 401    | Wrong challenge response or invalid/expired recovery token |
| 404    | Recovery not configured on this server     |
| 429    | Rate limit exceeded                        |

See `docs/opaque-api.yaml` for the full OpenAPI specification.

## Security Considerations

### User Enumeration

`POST /opaque/recovery/start` always returns `202 Accepted`, even if the credential
identifier is unknown. Your `RecoveryChallenger.sendChallenge()` implementation should
also avoid revealing whether the account exists — e.g. send a generic "if this account
exists, a code was sent" email.

### Rate Limiting

Recovery endpoints have their own dedicated rate limiter (separate from auth/registration)
with stricter defaults (3 tokens, 3 per 60 seconds refill). This prevents:
- Email flooding / SMS cost abuse
- Brute-force attempts on challenge codes

### Recovery Token Properties

| Property | Default    | Rationale                                       |
|----------|------------|-------------------------------------------------|
| TTL      | 10 minutes | Short window to limit exposure                  |
| Usage    | Single-use | Consumed on `registrationFinish`                |
| Scope    | Credential | Token bound to the credential it was issued for |
| Capacity | 10,000     | Prevents memory exhaustion                      |

### Challenge Response Security

Your `RecoveryChallenger.verifyResponse()` implementation should:
- Use constant-time comparison (`MessageDigest.isEqual` in Java, `subtle::ConstantTimeEq`
  in Rust) to prevent timing attacks
- Consume challenges on first verification attempt (prevent replay)
- Expire challenge codes after a short window (e.g. 10 minutes)
- Use cryptographically random codes of sufficient length (6+ digits)

### No OPAQUE Protocol Changes

Recovery does not modify the OPAQUE protocol. The `hofmann-rfc` module is completely
untouched. Recovery is purely a server-side authorization mechanism that gates access to
the existing registration flow.
