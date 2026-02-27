# hofmann-testserver

A local developer test server for exercising OPAQUE and OPRF clients against a real running
instance of `hofmann-dropwizard`. Start it with Docker Compose and interact with it via the
bundled Gradle CLI tasks.

## Starting the Server

From the project root:

```bash
cd hofmann-testserver
docker compose up --build
```

The server exposes two ports:

| Port | Purpose |
|------|---------|
| 8080 | Application (OPAQUE, OPRF, and protected endpoints) |
| 8081 | Admin (Dropwizard health checks and metrics) |

Wait until you see a line like:

```
hofmann-testserver  | INFO  [...] Started @Xms
```

Then leave the server running and open a second terminal for the CLI commands below.

### Overriding Keys

The server ships with stable hard-coded test keys baked into `config/config.yml` as defaults.
To rotate them, export any or all of the following environment variables **before** running
`docker compose up`:

```bash
export SERVER_KEY_SEED_HEX=<64 hex chars>
export OPRF_SEED_HEX=<64 hex chars>
export OPRF_MASTER_KEY_HEX=<64 hex chars>
export JWT_SECRET_HEX=<64 hex chars>

cd hofmann-testserver
docker compose up --build
```

> **Important**: Changing keys between runs invalidates all previously registered OPAQUE
> credentials. Re-register after any key rotation.

---

## OPRF CLI

The OPRF CLI sends an input string to the server's `POST /oprf` endpoint and prints the
resulting hash. The same input always produces the same hash as long as the server's OPRF
master key has not changed.

### Usage

```
./gradlew :hofmann-testserver:runOprfCli --args="<input> [--server <url>]" -q
```

| Option | Default | Description |
|--------|---------|-------------|
| `<input>` | _(required)_ | The string to hash |
| `--server <url>` | `http://localhost:8080` | Server base URL |

### Examples

```bash
# Hash a string (server must be running)
./gradlew :hofmann-testserver:runOprfCli --args="my-sensitive-data" -q

# Hash against a non-default server
./gradlew :hofmann-testserver:runOprfCli \
    --args="my-sensitive-data --server http://localhost:9090" -q
```

### Sample Output

```
Server : http://localhost:8080
Input  : my-sensitive-data

Result:
  processor  : hofmann-testserver
  request-id : <uuid>
  hash (hex) : 3a7f2c...
```

The same input always yields the same `hash (hex)` value on the same server instance.
Different inputs yield different hashes.

---

## OPAQUE CLI

The OPAQUE CLI exercises the full OPAQUE-3DH protocol. It supports three sub-commands:

| Command | What it does |
|---------|-------------|
| `register` | Register a credential with the server |
| `login` | Authenticate and print the session key and JWT token |
| `whoami` | Full round-trip: register → authenticate → call `GET /api/whoami` with the JWT |

### Usage

```
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="<command> <credentialId> <password> [options]" -q
```

**Positional arguments** (all required):

| Argument | Description |
|----------|-------------|
| `<command>` | `register`, `login`, or `whoami` |
| `<credentialId>` | A unique identifier for this credential (e.g. an email address) |
| `<password>` | The password to register or authenticate with |

**Options** (must match server configuration):

| Option | Default | Description |
|--------|---------|-------------|
| `--server <url>` | `http://localhost:8080` | Server base URL |
| `--context <string>` | `hofmann-testserver` | OPAQUE context string |
| `--memory <kib>` | `65536` | Argon2id memory in KiB |
| `--iterations <n>` | `3` | Argon2id iterations |
| `--parallelism <n>` | `1` | Argon2id parallelism |

> The defaults match `config/config.yml` exactly. See [Argon2id consistency](#argon2id-consistency)
> below before changing any of these options.

### Examples

```bash
# Register a credential
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="register alice@example.com hunter2" -q

# Authenticate and print the session key + JWT
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="login alice@example.com hunter2" -q

# Full end-to-end round-trip (register + authenticate + call /api/whoami)
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="whoami alice@example.com hunter2" -q
```

### Sample Output — `register`

```
Server  : http://localhost:8080
Context : hofmann-testserver
Argon2id: memory=65536 KiB, iterations=3, parallelism=1

Registering credential...
Registration successful.
```

### Sample Output — `login`

```
Server  : http://localhost:8080
Context : hofmann-testserver
Argon2id: memory=65536 KiB, iterations=3, parallelism=1

Authenticating...
Authentication successful.
  session key : <base64>
  JWT token   : eyJ...
```

### Sample Output — `whoami`

```
Server  : http://localhost:8080
Context : hofmann-testserver
Argon2id: memory=65536 KiB, iterations=3, parallelism=1

Registering credential...
Authenticating...
Authentication successful.
Calling GET /api/whoami with JWT...
  HTTP status : 200
  Body        : {"credentialIdentifier":"alice@example.com"}
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (network failure, bad arguments, etc.) |
| 2 | Security failure — wrong password or server/client parameter mismatch |

---

## Argon2id Consistency

The OPAQUE protocol runs the Argon2id key-stretching function **on the client**, not on the
server. The output feeds directly into the protocol's cryptographic binding. This means the
four Argon2id parameters — **context**, **memory**, **iterations**, and **parallelism** —
must be identical between registration and every subsequent login, and they must also match
the server's configured values.

If they do not match, registration appears to succeed but authentication will fail with a
`SecurityException` (exit code 2). There is no server-side error message that distinguishes
a wrong password from a parameter mismatch — this is intentional for security.

The testserver's defaults (`config/config.yml`):

```yaml
context: hofmann-testserver
argon2MemoryKib: 65536
argon2Iterations: 3
argon2Parallelism: 1
```

The CLI defaults are hard-coded to match these values. If you change the server configuration
you must pass the matching `--context`, `--memory`, `--iterations`, and `--parallelism` flags
to every CLI invocation.

When building your own client, use `OpaqueClientConfig.withArgon2id(...)` — not
`OpaqueClientConfig.forTesting()`. `forTesting()` uses an identity KSF (no Argon2id) and
is incompatible with this server.

```java
OpaqueClientConfig config = OpaqueClientConfig.withArgon2id(
    "P256_SHA256",        // cipher suite
    "hofmann-testserver", // context — must match server
    65536,                // memory KiB — must match server
    3,                    // iterations — must match server
    1                     // parallelism — must match server
);
```
