# hofmann-demo

Self-contained Docker Compose environment that runs the hofmann server and the
TypeScript demo UI, both protected by TLS 1.3 via HAProxy. Intended for local
demos and security testing.

## Architecture

```
External              HAProxy (TLS 1.3)          Internal
:443  ─────────────►  demo frontend  ──────────►  demo-ui:80  (nginx)
                                                    ├─ /opaque/*  ──►  server:8080
                                                    ├─ /oprf       ──►  server:8080
                                                    ├─ /api/*      ──►  server:8080
                                                    └─ /*          ──►  demo.html

:8443 ─────────────►  api frontend   ──────────►  server:8080  (Dropwizard)
```

Three containers:

| Container | Image | Role |
|-----------|-------|------|
| `server`  | built from project root | Dropwizard OPRF/OPAQUE server |
| `demo-ui` | built from `hofmann-typescript/` | nginx serving the compiled demo page + reverse proxy to `server` |
| `haproxy` | `haproxy:3.0-alpine` | TLS 1.3 termination only |

HAProxy terminates TLS and forwards plaintext HTTP to the two backends. nginx in
`demo-ui` handles path-based routing so demo.html can use relative URLs with no
hardcoded server address. The server's admin port (8081) is internal only and
used only for the Docker health check.

## Prerequisites

- Docker with Compose v2
- `openssl` (for `make certs`)
- Port 443 and 8443 available (or override via `.env`)

## Quick start

```bash
cd hofmann-demo
make up
```

`make up` runs `make certs` first, then `docker compose up -d`. The first build
compiles the Java server (Gradle) and the TypeScript client (Node), so it takes
a few minutes. Subsequent builds use Docker layer cache and are much faster.

Wait about 30 seconds for the JVM to start. Docker Compose will not start
HAProxy or the demo-ui until the server health check passes, so once all three
containers show as running the environment is ready.

```bash
docker compose ps
```

Open the demo UI in a browser:

```
https://localhost
```

The certificate is self-signed, so the browser will show a security warning.
Accept it to proceed.

## Ports

| Port | Service | Notes |
|------|---------|-------|
| 443  | Demo UI | Browser demo page; `/opaque`, `/oprf`, `/api` proxied to server |
| 8443 | Raw API | Direct TLS access to the Dropwizard API endpoints |

Override ports without editing `docker-compose.yml` by copying `.env.example`
to `.env` and setting `DEMO_PORT` / `API_PORT`.

## Using the Java CLI against the demo

The server container's port 8080 is not published by default. To run the Gradle
CLI tasks against the demo server, add a temporary port mapping to the `server`
service in `docker-compose.yml`:

```yaml
  server:
    ports:
      - "8080:8080"
```

Then restart the service:

```bash
docker compose up -d server
```

Run the OPRF CLI (defaults to `http://localhost:8080`):

```bash
./gradlew :hofmann-testserver:runOprfCli --args="my-secret-data" -q
```

Run the OPAQUE CLI workflow:

```bash
./gradlew :hofmann-testserver:runOpaqueCli --args="register alice@example.com hunter2" -q
./gradlew :hofmann-testserver:runOpaqueCli --args="login    alice@example.com hunter2" -q
./gradlew :hofmann-testserver:runOpaqueCli --args="whoami   <token-from-login>" -q
```

Remove the `ports` mapping and restart when done to keep the server internal.

## Makefile targets

| Target  | What it does |
|---------|--------------|
| `certs` | Generate self-signed P-256 ECDSA cert → `haproxy/certs/demo.pem` |
| `build` | `docker compose build` |
| `up`    | `make certs && docker compose up -d` |
| `down`  | `docker compose down` |
| `clean` | `docker compose down -v && rm -rf haproxy/certs/` |
| `logs`  | `docker compose logs -f` |

## Certificates

`make certs` generates a self-signed P-256 ECDSA certificate valid for 365 days
with SANs for `localhost`, `hofmann-demo`, and `127.0.0.1`. The combined
PEM file (`cert + key`) is written to `haproxy/certs/demo.pem`, which is the
format HAProxy expects. The `haproxy/certs/` directory is git-ignored.

To use your own certificate, place the combined PEM at `haproxy/certs/demo.pem`
before running `make up` (or `docker compose up -d`).

## Environment variables

Copy `.env.example` to `.env` to override defaults without modifying any files.

| Variable | Default (in config.yml) | Purpose |
|----------|------------------------|---------|
| `DEMO_PORT` | `443` | Host port mapped to HAProxy :443 |
| `API_PORT`  | `8443` | Host port mapped to HAProxy :8443 |
| `SERVER_KEY_SEED_HEX`  | stable test value | OPAQUE server key seed |
| `OPRF_SEED_HEX`        | stable test value | OPAQUE OPRF seed |
| `OPRF_MASTER_KEY_HEX`  | stable test value | Standalone OPRF master key |
| `JWT_SECRET_HEX`       | stable test value | JWT signing secret |

The four key variables default to stable values so the server produces
consistent results across restarts during development. Generate fresh random
keys for any environment shared with others:

```bash
export SERVER_KEY_SEED_HEX=$(openssl rand -hex 32)
export OPRF_SEED_HEX=$(openssl rand -hex 32)
export OPRF_MASTER_KEY_HEX=$(openssl rand -hex 32)
export JWT_SECRET_HEX=$(openssl rand -hex 32)
make up
```

## Verifying the endpoints

```bash
# Demo UI responds
curl -k -s -o /dev/null -w "%{http_code}" https://localhost/
# → 200

# API endpoint reachable through HAProxy
curl -k -s -o /dev/null -w "%{http_code}" \
  -X POST https://localhost:8443/oprf \
  -H "Content-Type: application/json" \
  -d '{"serverId":"testserver","input":"dGVzdA=="}'
# → 200

# Path-based proxy through the demo UI frontend
curl -k -s -o /dev/null -w "%{http_code}" \
  -X POST https://localhost/oprf \
  -H "Content-Type: application/json" \
  -d '{"serverId":"testserver","input":"dGVzdA=="}'
# → 200
```
