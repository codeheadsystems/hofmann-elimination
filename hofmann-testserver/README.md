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
| `delete` | Delete a registration using a JWT token from a prior `login` |
| `whoami` | Call `GET /api/whoami` with a JWT token obtained from a prior `login` |

These commands form a natural workflow: `register` once, `login` to get a JWT, then use
`delete` to remove the registration or `whoami` to verify the JWT grants access to a protected endpoint.

### Usage — register / login

```
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="register|login <credentialId> <password> [options]" -q
```

| Argument / Option | Default | Description |
|-------------------|---------|-------------|
| `<credentialId>` | _(required)_ | Unique identifier for the credential (e.g. an email address) |
| `<password>` | _(required)_ | The password to register or authenticate with |
| `--server <url>` | `http://localhost:8080` | Server base URL |
| `--context <string>` | `hofmann-testserver` | OPAQUE context string |
| `--memory <kib>` | `65536` | Argon2id memory in KiB |
| `--iterations <n>` | `3` | Argon2id iterations |
| `--parallelism <n>` | `1` | Argon2id parallelism |

> The defaults match `config/config.yml` exactly. See [Argon2id consistency](#argon2id-consistency)
> below before changing any of these options.

### Usage — delete

```
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="delete <credentialId> <jwtToken> [--server <url>]" -q
```

`delete` sends `DELETE /opaque/registration` with the credential identifier and the JWT in
the `Authorization: Bearer` header. The server validates that the JWT subject matches the
credential being deleted, so you must supply a token obtained by logging in as that user.

### Usage — whoami

```
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="whoami <jwtToken> [--server <url>]" -q
```

`whoami` does not perform any OPAQUE protocol steps — it simply forwards the JWT token in an
`Authorization: Bearer` header to `GET /api/whoami` and prints the response body.

### Full workflow example

```bash
# 1. Register once
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="register alice@example.com hunter2" -q

# 2. Authenticate — copy the JWT token from the output
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="login alice@example.com hunter2" -q

# 3. Call the protected endpoint with the JWT
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="whoami eyJ..." -q

# 4. Delete the registration
./gradlew :hofmann-testserver:runOpaqueCli \
    --args="delete alice@example.com eyJ..." -q
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

### Sample Output — `delete`

```
Server : http://localhost:8080

Deleting registration...
Deletion successful.
```

### Sample Output — `whoami`

```
Server : http://localhost:8080

Calling GET /api/whoami...
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

The OPAQUE protocol runs Argon2id **on the client**. The context string and all three Argon2id
parameters must be identical between registration and every subsequent login, and must also
match the server's configured values. A mismatch causes silent authentication failure
indistinguishable from a wrong password (exit code 2).

The testserver's defaults (`config/config.yml`):

```yaml
context: hofmann-testserver
argon2MemoryKib: 65536
argon2Iterations: 3
argon2Parallelism: 1
```

The CLI defaults are hard-coded to match these values. If you change the server configuration
you must pass matching `--context`, `--memory`, `--iterations`, and `--parallelism` flags to
every CLI invocation.

For a full explanation of the failure modes and Java client setup, see
[USAGE.md — Argon2id consistency](../USAGE.md#argon2id-consistency-between-server-and-client).
