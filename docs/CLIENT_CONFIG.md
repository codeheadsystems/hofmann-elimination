# Client Configuration

How to configure the Java and TypeScript clients, and the parameters that must agree with the
server when you bypass auto-configuration.

> [Server configuration](../USAGE.md) · **Client configuration** · [Framework integration](INTEGRATION.md) · [Key management](KEY_MANAGEMENT.md) · [Doc map](README.md)

---

## Auto-configuration (recommended)

Both `HofmannOpaqueClientManager` and `HofmannOprfClientManager` auto-configure themselves
on first use by calling the server's config endpoint (`GET /opaque/config` or
`GET /oprf/config`).  The response is cached per server, so the endpoint is hit exactly
once regardless of how many operations follow.

```java
// OPAQUE — no config needed; cipher suite, context, and Argon2id params
// are fetched automatically from GET /opaque/config on first use.
HofmannOpaqueClientManager opaqueManager =
    new HofmannOpaqueClientManager(opaqueAccessor);

// OPRF — cipher suite fetched from GET /oprf/config on first use.
HofmannOprfClientManager oprfManager =
    new HofmannOprfClientManager(oprfAccessor);
```

Both classes are `@Singleton`-annotated and suitable for injection by Dagger, Guice, or
Spring.  The accessor requires only a `Map<ServerIdentifier, ServerConnectionInfo>` that
maps each logical server name to its base URL — no cipher suite or Argon2id parameters
needed.

## TypeScript / browser

The TypeScript clients have matching factory methods:

```typescript
// OPAQUE — fetches /opaque/config and configures KSF automatically
const opaqueClient = await OpaqueHttpClient.create('https://api.example.com');
// opaqueClient.configResponse holds the parsed OpaqueConfigResponseDto if needed

// OPRF — fetches /oprf/config and stores it in cachedConfig
const oprfClient = await OprfHttpClient.create('https://api.example.com');
// oprfClient.cachedConfig holds { cipherSuite: string } if needed
```

## Per-server config overrides (CLI / advanced use)

For tools that must work offline or where specific parameters must be pinned, supply a
`Map<ServerIdentifier, OpaqueClientConfig>` (or `OprfClientConfig`) as the second argument.
Servers present in the map skip the auto-fetch; others still auto-fetch.

```java
// Pins exact parameters for one server; other servers are still auto-fetched.
Map<ServerIdentifier, OpaqueClientConfig> overrides = Map.of(
    myServerId,
    OpaqueClientConfig.withArgon2id("P256_SHA256", "my-app", 65536, 3, 1)
);
HofmannOpaqueClientManager manager =
    new HofmannOpaqueClientManager(accessor, overrides);
```

This is the pattern used by the `OpaqueCli` / `OprfCli` command-line tools.

---

## Argon2id consistency between server and client

The Argon2id KSF runs **on the client**, not the server.  The client calls it during both
registration (`finalizeRegistration`) and authentication (`generateKE3`) to derive
`randomizedPwd`:

```
randomizedPwd = HKDF-Extract("", oprfOutput || Argon2id(oprfOutput))
```

The server never executes Argon2id.  It stores only the already-stretched output
(inside the `envelope` and `maskingKey`).

**When using auto-configuration** (the default), the client fetches these parameters from
`GET /opaque/config` and applies them automatically.  No manual alignment is required.

**When using config overrides**, the parameters must match the server exactly.  A mismatch
causes silent authentication failures:

- **Registration appears to succeed** — the server stores whatever the client sends.
- **Authentication always fails** — the client derives a different `randomizedPwd` and
  therefore a different `maskingKey`.  The OPAQUE MAC check fails with a `SecurityException`,
  indistinguishable from a wrong password.

### Parameters that must match (override path only)

| Server config field | `OpaqueClientConfig` factory argument |
|---------------------|---------------------------------------|
| `opaqueCipherSuite` | `withArgon2id(suiteName, ...)`        |
| `context`           | `withArgon2id(..., context, ...)`     |
| `argon2MemoryKib`   | `withArgon2id(..., memory, ...)`      |
| `argon2Iterations`  | `withArgon2id(..., iterations, ...)`  |
| `argon2Parallelism` | `withArgon2id(..., parallelism, ...)` |

### Test-only shortcut (identity KSF)

`OpaqueClientConfig.forTesting(context)` uses identity KSF (no Argon2). It only works against a
server with `argon2MemoryKib: 0`, which additionally requires `allowIdentityKsf` or the server
refuses to start. A client negotiating configuration from such a server also needs
`allowWeakServerKsf` — see [SECURITY.md](../SECURITY.md). Do not use it against the
`hofmann-testserver` (which has Argon2 enabled) or any production server.

### Changing Argon2id parameters

Changing any Argon2id parameter after users have registered **invalidates all existing
registrations**.  Every affected user must re-register from scratch.  Plan parameter
upgrades (e.g., increasing memory cost) as a full re-registration migration.
