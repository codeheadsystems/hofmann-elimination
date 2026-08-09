# Integration Test Plan

End-to-end validation steps for the three implementations in this repository:

- **Java** — `hofmann-rfc`, `hofmann-client`, `hofmann-server`, `hofmann-dropwizard`,
  `hofmann-springboot`, `hofmann-integration-tests`
- **TypeScript** — `hofmann-typescript` (browser/Node client)
- **Rust** — `hofmann-rust` (`hofmann-rfc` crate)

The plan is split into:

1. **Automated test suites** — fast, run these first on any change.
2. **`hofmann-testserver` validation** — exercise the Java server with the bundled CLIs.
3. **`hofmann-demo` validation** — exercise the TypeScript browser client against the
   Java server behind HAProxy/TLS.

Run the automated suites before either manual environment. If any automated suite
fails, fix it before proceeding.

---

## 0. Prerequisites

| Tool | Version | Used by |
|------|---------|---------|
| JDK  | 21+     | Java build, gradle |
| Node | 20+     | TypeScript build, demo |
| Rust | stable (1.75+) | Rust crate |
| Docker + Compose v2 | recent | testserver, demo |
| `openssl` | any    | demo TLS cert generation |

All commands below assume the repository root as the working directory unless
otherwise noted.

---

## 1. Automated test suites

### 1a. Java unit + integration tests

```bash
./gradlew clean build test
```

This runs unit tests for every Java module plus the cross-suite integration
tests in `hofmann-integration-tests` (P-256, P-384, P-521, ristretto255 — OPRF,
OPAQUE, key-rotation, and cross-client variants). A green build is the bar
for the Java side.

To target only the cross-suite integration tests:

```bash
./gradlew :hofmann-integration-tests:test
```

### 1b. TypeScript

```bash
cd hofmann-typescript
npm install
npm run typecheck
npm test
npm run build
```

`npm test` runs vitest against the OPRF, OPAQUE, integration, and cross-client
test vectors. `npm run build` must also succeed — the demo and the published
package both consume the build output.

### 1c. Rust

```bash
cd hofmann-rust
cargo test
```

Covers `hofmann-rfc` library tests + integration tests under `tests/`
(`opaque_roundtrip`, `oprf_roundtrip`, `recovery`).

### 1d. Cross-language compatibility

The TypeScript test suite includes a `cross-client.test.ts` that asserts byte-
for-byte agreement with the RFC vectors used by the Java side. The Java
`hofmann-integration-tests` also include `*CrossClient*Test` classes. Running
1a + 1b is sufficient to validate cross-language wire compatibility for the
test-vector cases.

---

## 2. `hofmann-testserver` validation

Exercises the running Dropwizard server end-to-end via the bundled Gradle
CLI tasks. Use this when changes touch any server-side code path or wire
format.

### 2.1 Start the server

```bash
cd hofmann-testserver
docker compose up --build
```

Wait for `Started @Xms` in the logs. Leave this terminal running.
Open a second terminal at the repo root for the CLI commands below.

> Optional: rotate keys with `SERVER_KEY_SEED_HEX` / `OPRF_SEED_HEX` /
> `OPRF_MASTER_KEY_HEX` / `JWT_SECRET_HEX` env vars before `docker compose up`.
> Rotation invalidates any previously registered credentials.

### 2.2 OPRF — deterministic hashing

```bash
./gradlew :hofmann-testserver:runOprfCli --args="my-sensitive-data" -q
```

Manual checks:

- [ ] Output prints `processor`, `request-id`, and a hex `hash`.
- [ ] Re-running the same input produces the **same** hex hash.
- [ ] Changing one character of the input produces a **different** hex hash.
- [ ] Restarting the server with a different `OPRF_MASTER_KEY_HEX` changes
      the hash for the same input (then revert if you don't want to lose
      registrations).

### 2.3 OPAQUE — register / login / whoami / delete

Run the four commands in sequence, copying the JWT from step 2 into steps 3 and 4:

```bash
./gradlew :hofmann-testserver:runOpaqueCli --args="register alice@example.com hunter2" -q
./gradlew :hofmann-testserver:runOpaqueCli --args="login    alice@example.com hunter2" -q
./gradlew :hofmann-testserver:runOpaqueCli --args="whoami   <jwt-from-login>" -q
./gradlew :hofmann-testserver:runOpaqueCli --args="delete   alice@example.com <jwt-from-login>" -q
```

Manual checks:

- [ ] `register` prints "Registration successful." (exit 0).
- [ ] `login` prints "Authentication successful." with a base64 `session key`
      and a JWT.
- [ ] `whoami` returns HTTP 200 with body `{"credentialIdentifier":"alice@example.com"}`.
- [ ] `delete` prints "Deletion successful." (exit 0).
- [ ] After delete, `login` for the same credential exits with code **2**
      (security failure, not a generic error).

### 2.4 OPAQUE — failure modes

- [ ] **Wrong password**: `login alice@example.com WRONG-pass` → exit code **2**.
- [ ] **Argon2id mismatch**: re-register, then login with `--memory 32768`
      (server still configured for 65536) → exit code **2**.
      The failure must be indistinguishable from a wrong password.
- [ ] **Context mismatch**: register with default context, then login with
      `--context something-else` → exit code **2**.
- [ ] **Stale JWT after delete**: delete the registration, then call
      `whoami <old-jwt>`. The server may still accept the JWT until expiry
      (JWTs are stateless) — note observed behavior.
- [ ] **Whoami without token**: `whoami badtoken` → HTTP 401 from the server.

### 2.5 Tear down

```bash
cd hofmann-testserver
docker compose down
```

---

## 3. `hofmann-demo` validation

Exercises the TypeScript browser client against the Java server, both
fronted by HAProxy with TLS 1.3. Use this whenever changes touch
`hofmann-typescript`, the demo HTML/JS, the server's HTTP surface, or the
HAProxy/nginx routing.

### 3.1 Bring up the demo stack

```bash
cd hofmann-demo
make up
```

`make up` runs `make certs` (self-signed P-256 cert) and then
`docker compose up -d`. The first run builds the Java server image and the
TypeScript demo bundle, so it takes a few minutes. Wait until all three
containers are healthy:

```bash
docker compose ps
```

Open https://localhost in a browser and accept the self-signed certificate.

### 3.2 Smoke checks

```bash
# Demo UI loads
curl -k -s -o /dev/null -w "%{http_code}\n" https://localhost/
# → 200

# OPRF endpoint reachable through demo path-routing
curl -k -s -o /dev/null -w "%{http_code}\n" https://localhost/oprf/config
# → 200

# OPRF endpoint reachable directly via API frontend
curl -k -s -o /dev/null -w "%{http_code}\n" https://localhost:8443/oprf/config
# → 200
```

> These are **reachability** checks — they confirm routing and TLS termination, not the protocol.
> `POST /oprf` cannot be smoke-tested with curl: its body is `{"ecPoint","requestId"}` where
> `ecPoint` is a hex-encoded blinded curve point the client must compute. Use the CLI or the
> TypeScript client to exercise the protocol itself.


- [ ] All three return `200`.

### 3.3 Manual UI test plan

Open https://localhost. The page is the OPAQUE demo from
`hofmann-typescript/demo.html`. Follow the steps in order — most cards
depend on a prior step.

#### Server Configuration card

- [ ] On page load, `Cipher Suite`, `OPAQUE Context`, and the three Argon2
      fields auto-populate from `GET /opaque/config`. None should remain `—`/`0`.
- [ ] The status chip turns green (`OK`/`Loaded`).
- [ ] The Protocol Flow panel on the right shows non-`—` values for Curve,
      Hash, KSF.

#### 1. OPAQUE Registration

- [ ] Defaults are `alice@example.com` / `correct-horse-battery`.
- [ ] Click **Register**. Status chip cycles `Idle → Running → OK`.
- [ ] Activity log shows the wire steps (blindedElement, evaluatedElement,
      record).
- [ ] Re-clicking **Register** for the same credential produces an error
      result (already registered) — credential ID is unique.

#### 2. OPAQUE Authentication

- [ ] Click **Authenticate** with the registered credential. Status `OK`.
- [ ] A JWT appears in the `JWT Token` box.
- [ ] **Copy** button copies the token to the clipboard.
- [ ] The token also auto-fills into card 3 (Change Password) and is
      available for cards 5 (Whoami) and 6 (Delete).
- [ ] Authenticate with the **wrong** password → status `ERR`, no token,
      activity log shows the auth failure.

#### 3. Change Password

- [ ] With the JWT from step 2 and a new password, click
      **Change Password**. Status `OK`.
- [ ] Re-authenticate (card 2) with the **old** password → `ERR`.
- [ ] Re-authenticate with the **new** password → `OK`. Save the new JWT.
- [ ] Old JWT is now invalid for card 5 / card 6 (sessions revoked on
      password change).

#### 4. Account Recovery

The default challenge code in the testserver/demo accepts a fixed
deterministic value. Confirm the expected code from
`hofmann-testserver/config/config.yml` (or the demo server's recovery
challenger). The default in the form is `123456`.

- [ ] With the registered credential, a new password, and the correct
      challenge code, click **Recover & Re-register**. Status `OK`.
- [ ] Authenticate (card 2) with the recovery password → `OK`.
- [ ] Try recovery again with a wrong code → status `ERR`.

#### 5. Whoami (testserver only)

- [ ] Paste the latest JWT, click **GET /api/whoami**. Response should be
      `{"credentialIdentifier":"alice@example.com"}`, HTTP 200.
- [ ] Tamper with the token (change one char) → status `ERR`, HTTP 401.
- [ ] Empty token → button still posts; expect 401.

#### 6. Delete Registration

- [ ] With a valid JWT, click **Delete**. Status `OK`.
- [ ] After deletion, **Authenticate** (card 2) with the same credential →
      `ERR` (no such registration / generic auth failure).
- [ ] **Whoami** with the now-stale JWT — note observed behavior. JWTs are
      typically stateless and may still validate until expiry.

#### OPRF (standalone)

- [ ] Default input `my-secret-data`. Click **Evaluate**. Status `OK`,
      hex output appears.
- [ ] Re-clicking with the same input produces the **same** hex output.
- [ ] Changing the input produces a **different** hex output.

#### Activity log

- [ ] Each action above produced step-by-step entries (blindedElement,
      evaluatedElement, KE1/KE2/KE3, etc.).
- [ ] **Clear** empties the log.

### 3.4 Browser cross-checks

- [ ] Open DevTools → Network. Confirm requests are made to `https://localhost`
      with HTTP/2 (HAProxy default) and TLS 1.3 (Security tab).
- [ ] No console errors during any of the steps above.
- [ ] Open in a second browser (or private window) — registration state from
      the first session is visible (server-side state), but the JWT must be
      re-acquired.

### 3.5 Tear down

```bash
cd hofmann-demo
make down            # stop containers, keep volumes/certs
# or
make clean           # stop, drop volumes, delete certs/
```

---

## 4. Quick TypeScript-only demo (no Docker)

For rapid iteration on the demo UI without rebuilding the Docker stack —
useful when the only changes are in `hofmann-typescript/`.

Prereq: a running server on `http://localhost:8080`. Easiest way to get one:

```bash
cd hofmann-testserver
docker compose up --build      # leaves server on :8080
```

Then in another terminal:

```bash
cd hofmann-typescript
npm run demo
```

Vite serves the demo at the URL it prints (typically http://localhost:5173)
and proxies `/opaque`, `/oprf`, and `/api` to `localhost:8080`. The Server
URL field in the UI should be left **blank** in proxy mode.

Run a subset of the manual steps from §3.3 to validate UI changes. This
mode skips HAProxy/TLS but exercises the full TypeScript client and Java
server.

---

## 5. Sign-off checklist

Before tagging a release or merging a substantial change, all of the
following should be green:

- [ ] §1a `./gradlew clean build test`
- [ ] §1b `npm run typecheck && npm test && npm run build`
- [ ] §1c `cargo test`
- [ ] §2 testserver: OPRF + OPAQUE register/login/whoami/delete + failure modes
- [ ] §3 demo: all six numbered cards + OPRF panel + activity log
- [ ] §3.2 smoke `curl` checks return 200
- [ ] No new console errors or unexpected log entries in either environment
