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

### Targeted lockout, and the challenge id that closes it

**Deliver the challenge id if you can.** This is the one place where the default
`RecoveryChallenger` shape carries a real residual. Note this is **off unless you deliver the
id** — a deployment that does nothing keeps the identifier-keyed behaviour and the lockout below
in full.

Both recovery endpoints are unauthenticated, and the only thing the caller supplies is the
credential identifier. Rate-limiting on that identifier is right for bounding guessing
against one account and wrong given who the caller might be: a handful of requests naming a
victim spend **that victim's** budget, so the victim cannot complete a recovery they
legitimately started — without ever having been involved in the attack.

It cannot be fixed by rate-limiting differently. Before a challenge exists there is nothing
to key on that an attacker cannot also supply. What breaks it is a value the server
generates and delivers *out of band*.

`recoveryStart` generates a random challenge id, **records it**, and passes it to
`sendChallenge(credentialIdentifier, challengeId)`. Deliver it to the user alongside the
challenge — embedded in the recovery link is the usual shape. The client presents it at
`recoveryVerify`; the server checks it is an id it actually issued for that credential, and only
then keys the verification limiter on it. An attacker naming a victim spends their own budget;
spending the victim's costs them a 122-bit guess, and a fabricated id is refused as a limiter key
rather than becoming a fresh bucket.

There is **no capability flag to set.** An earlier design had one and it was a trap: declaring it
told the server to key the limiter on the id, but the server had no way to tell an issued id from
a fabricated one — only the challenger could, and the limiter runs first. Recording the ids moves
that check to where it can actually be made.

```java
public class EmailChallenger implements RecoveryChallenger {

  @Override
  public void sendChallenge(byte[] credentialIdentifier, String challengeId) {
    String code = randomSixDigitCode();
    challenges.put(challengeId, new Challenge(credentialIdentifier, code, Instant.now()));
    // The id must reach the user, or they cannot present it at verification.
    email(credentialIdentifier,
        "Recovery code " + code + ": https://example.com/recover?c=" + challengeId);
  }

  @Override
  public boolean verifyResponse(byte[] credentialIdentifier, String challengeId,
                                String challengeResponse) {
    Challenge challenge = challenges.remove(challengeId);       // single use
    return challenge != null
        && !challenge.isExpired()
        && Arrays.equals(challenge.credentialIdentifier(), credentialIdentifier)
        && MessageDigest.isEqual(challenge.code().getBytes(UTF_8),
                                 challengeResponse.getBytes(UTF_8));
  }

  // The two-argument methods remain the interface's required surface. The manager always calls
  // the three-argument ones, so these are unreachable once you override both.
  @Override public void sendChallenge(byte[] id) { throw new UnsupportedOperationException(); }
  @Override public boolean verifyResponse(byte[] id, String r) { throw new UnsupportedOperationException(); }
}
```

**Still bind the response to the challenge.** `verifyResponse` should check that the response
belongs to the challenge named by `challengeId`, not merely that it is a valid response for the
identifier — otherwise a caller could pair a stolen or replayed code with an id of their choosing.
The server has already checked that the id is one it issued for this credential, so what is left
to you is tying the response to that specific challenge. Failing to do so is an ordinary bug with
an ordinary symptom, not a silent weakening of the limiter.

**Residuals, all real:**

- **`recoveryStart` is still identifier-keyed**, because at that point no challenge exists. An
  attacker can exhaust a victim's *start* budget and stop them requesting a **new** challenge for
  a while. The two endpoints draw from separate buckets, so this no longer blocks completing a
  challenge already in flight. Letting an unauthenticated caller trigger an email at all is what
  costs this. Note also that splitting the buckets doubles the total unauthenticated request
  budget per identifier; the *guessing* budget that matters is unchanged.
- **A leaked challenge id re-opens the lockout for that recovery, and can be attributed to an
  account.** The id travels in a link, so it can reach a `Referer` header, a proxy log, or browser
  history. Whoever has it can drain `challenge:<id>` and lock the victim out of the recovery
  *already in progress* — the exact harm this removes in the non-leaking case.

  They can also learn *whose* it is. Only an id matching the named credential charges the
  `challenge:` bucket; absent, unknown and mismatched ids all charge `verify:<named>`. So a holder
  can drain `verify:<candidate>` and then present the id against that candidate: a `429` means the
  id is not bound to it, a `401` means it is. Credential identifiers are usually email addresses,
  so candidates are guessable, and this turns a leaked id into a confirmed id-to-account pair.

  This is **not fixed, deliberately.** That distinguisher *is* the protection — a user holding a
  matching id sits on a bucket immune to a drained identifier bucket, and charging both buckets on
  the matched path would close the oracle by reintroducing the lockout. It costs the attacker a
  drained candidate bucket per probe, which is noisy and locks that candidate out meanwhile, and
  it yields identity disclosure only: it does not speed up guessing the code. Treat the recovery
  link like the code it carries.
- **If you never deliver the id**, the client cannot present one, the manager keys on the
  credential identifier as before, and the targeted lockout is live for your deployment.
- **In a cluster you must supply a distributed `RecoveryChallengeStore`.** Pass it to the
  `HofmannOpaqueServerManager` constructor; the default is in-memory and single-node. If
  `recoveryStart` and `recoveryVerify` land on different nodes with an unshared store, the id is
  unknown on the verifying node, keying falls back to the identifier, and the lockout is live
  again — with nothing failing to say so. Most production deployments are multi-node, so for most
  deployments this is the difference between the protection working and quietly not.
- **Your `verifyResponse` must check both halves.** That the response belongs to the challenge
  named by `challengeId`, *and* that the challenge belongs to the credential identifier. The
  server refuses a request whose id it issued for a different credential, but treat that as
  defence in depth: it cannot help when the id is one the server never recorded, which is the
  normal case on a multi-node deployment with an unshared store. Without your check, a caller
  holding a genuine id for their own account could present it against someone else's identifier
  and have you check their guess against the victim's code.
- **The store bounds a flood by evicting, not refusing.** At capacity the oldest outstanding
  challenge is dropped, and one credential identifier cannot hold more than
  `DEFAULT_MAX_PER_IDENTIFIER` (32) at once. An earlier version refused to record at capacity,
  which meant a flood silently returned *every* subsequent recovery to identifier keying rather
  than costing one.

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
