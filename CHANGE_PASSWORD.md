# Change Password Feature

## Overview

OPAQUE never exposes the password to the server, so "changing a password" is a
**re-registration with a new password**, authorized by proving knowledge of the
current password via a valid JWT from a prior authentication.

## Protocol Flow

```
Client                                   Server
  |                                        |
  |── authenticate(oldPassword) ──────────>|  (standard OPAQUE auth -> JWT)
  |<── JWT ────────────────────────────────|
  |                                        |
  |── POST /opaque/password/start ────────>|  (JWT auth + blinded element)
  |   Authorization: Bearer <jwt>          |
  |<── RegistrationStartResponse ─────────|  (evaluated element + server public key)
  |                                        |
  | [client derives new randomized_pwd,    |
  |  creates new envelope + keys]          |
  |                                        |
  |── POST /opaque/password/finish ───────>|  (JWT auth + new registration record)
  |   Authorization: Bearer <jwt>          |
  |<── 204 No Content ────────────────────|  (old record replaced, sessions revoked)
```

## Endpoints

### `POST /opaque/password/start`

Accepts the client's credential identifier and blinded OPRF element for a new
password. Returns the server's OPRF-evaluated element and long-term public key.

- **Request body:** `RegistrationStartRequest` (same as registration)
- **Response body:** `RegistrationStartResponse` (same as registration)
- **Authorization:** `Bearer <jwt>` required; subject must match credential identifier
- **Errors:** 400 (bad request), 401 (unauthorized), 429 (rate limited)

### `POST /opaque/password/finish`

Atomically replaces the old registration record, revokes all active JWT sessions
for the credential, and stores the new registration record.

- **Request body:** `RegistrationFinishRequest` (same as registration)
- **Response:** `204 No Content`
- **Authorization:** `Bearer <jwt>` required; same JWT used in `/password/start`
- **Errors:** 400 (bad request), 401 (unauthorized)

## Design Decisions

1. **Dedicated endpoints** rather than overloading existing registration endpoints.
   This avoids ambiguity between recovery tokens and JWTs, allows separate rate
   limiting, and provides clearer API semantics.

2. **JWT-based authorization.** The user authenticates with their current password
   to obtain a JWT, which proves knowledge of the old password without the server
   ever seeing it.

3. **Atomic replacement.** The finish endpoint atomically deletes the old record,
   revokes all sessions, and stores the new record. The user must re-authenticate
   after changing their password.

4. **No new DTOs.** Request/response bodies are identical to the registration
   endpoints. The only difference is the mandatory `Authorization: Bearer <jwt>` header.

5. **No changes to hofmann-rfc.** The OPAQUE crypto layer already supports
   re-registration — password change is just registration at the crypto level.

## Implementation by Module

### hofmann-server

- **`HofmannOpaqueServerManager`** — `changePasswordStart()` and `changePasswordFinish()`
  methods that validate the JWT, check subject matches the credential, and delegate
  to the existing registration crypto.
- **`OpaqueResource`** (JAX-RS) — thin adapter mapping `POST /password/start` and
  `POST /password/finish` to the manager. Exception mapping: SecurityException -> 401,
  IllegalArgumentException -> 400.
- **`OpaqueController`** (Spring Boot) — same endpoints as Spring `@PostMapping` methods.

### hofmann-client

- **`HofmannOpaqueAccessor`** — `changePasswordStart()` and `changePasswordFinish()`
  HTTP transport methods targeting `/opaque/password/start` and `/opaque/password/finish`.
- **`HofmannOpaqueClientManager`** — high-level `changePassword(serverId, credentialId,
  newPassword, bearerToken)` method that orchestrates the full three-step flow.

### hofmann-typescript

- **`OpaqueHttpClient.changePassword(credentialId, newPassword, token)`** — full
  orchestration: creates registration request, POSTs to `/password/start` with JWT,
  finalizes registration locally, POSTs to `/password/finish` with JWT.

### hofmann-testserver

- **`OpaqueCli`** — `change-password` command that authenticates with the old password,
  then re-registers with the new password.

### Demo UI

- **`demo.html` / `demo.ts`** — Change Password card (step 3) with credential ID,
  new password, and JWT token fields. JWT is auto-filled from a prior authentication.

### OpenAPI Spec

- **`docs/opaque-api.yaml`** — Password Change tag and endpoint definitions for
  `/opaque/password/start` and `/opaque/password/finish`.

## Usage Examples

### Java Client

```java
// Step 1: Authenticate with current password
AuthFinishResponse auth = manager.authenticate(serverId, credentialId, oldPassword);

// Step 2: Change password using the JWT
manager.changePassword(serverId, credentialId, newPassword, auth.token());

// Step 3: Re-authenticate with new password
AuthFinishResponse newAuth = manager.authenticate(serverId, credentialId, newPassword);
```

### TypeScript Client

```typescript
// Step 1: Authenticate with current password
const { token } = await client.authenticate(credentialId, oldPassword);

// Step 2: Change password using the JWT
await client.changePassword(credentialId, newPassword, token);

// Step 3: Re-authenticate with new password
const newAuth = await client.authenticate(credentialId, newPassword);
```

### CLI

```bash
./gradlew :hofmann-testserver:runOpaqueCli \
  --args="change-password alice@example.com oldpass newpass" -q
```

## Security Properties

- **No password exposure:** The server never sees the old or new password. The JWT
  proves knowledge of the old password; the OPRF registration proves knowledge of
  the new password.
- **Subject matching:** Both endpoints verify the JWT subject matches the credential
  identifier, preventing user A from changing user B's password.
- **Session revocation:** All existing sessions are revoked on password change,
  ensuring that compromised sessions are invalidated.
- **Rate limiting:** Password change endpoints are rate-limited to prevent abuse.
