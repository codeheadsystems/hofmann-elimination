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

> **One exception.**  The verifiable OPRF modes need the server's public key, and that
> cannot be auto-configured — a key fetched from the server it authenticates proves
> nothing.  See [Verifiable modes](#verifiable-modes-the-server-public-key-must-be-pinned)
> below.  Base-mode OPRF and OPAQUE are fully auto-configurable.

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
// oprfClient.cachedConfig holds { cipherSuite, modes? } if needed
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

## Verifiable modes: the server public key must be pinned

Auto-configuration covers everything above because none of it is a secret and none of it
is load-bearing for security — a wrong cipher suite fails loudly.  The verifiable OPRF
modes are different, and this is the one place where "just fetch it" is not available.

VOPRF and POPRF let a client check that the server evaluated with the key it publicly
committed to.  That check is worth nothing if the key comes from the same server, over the
same connection, as the proof it authenticates: a server able to choose both can produce a
verifying pair for any key it likes.  RFC 9497 §7.3 notes it can do this **per client**,
which partitions users into individually identifiable buckets while every proof still
verifies.

So the key must reach the client **out of band**, authenticated by something other than
this connection — checked into the client's configuration, shipped in a signed bundle,
delivered by whatever channel already carries your other trust anchors.  See
[Key management](KEY_MANAGEMENT.md) for the server-side half.

```java
OprfClientConfig config = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build())
    .withVoprfServerPublicKey("03e17e70604bcabe...")   // out of band, not fetched
    .withPoprfServerPublicKey("02c5e5300c2d9e6b...");

HofmannOprfClientManager manager =
    new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, config));

// Batched: one DLEQ proof covers the whole batch.
List<HofmannHashResult> results =
    manager.performVerifiableHash(List.of(inputA, inputB), SERVER_ID);

// POPRF adds a public input. Empty means "no public input" — it is a real value,
// distinct from every other, and is required rather than defaulted.
HofmannHashResult scoped =
    manager.performPartiallyObliviousHash(input, "tenant-a".getBytes(UTF_8), SERVER_ID);
```

```typescript
const client = await OprfHttpClient.create('https://api.example.com', {
  voprfServerPublicKey: fromHex('03e17e70604bcabe...'),  // out of band, not fetched
});

const outputs = await client.evaluateVerifiable([inputA, inputB]);
```

`OprfClientConfig.fromServerConfig` deliberately carries the cipher suite across and
nothing else.  There is no code path in either client from an HTTP response into a pinned
key, and that is checkable by reading one method.

### What the config cross-check does and does not do

`GET /oprf/config` advertises the enabled modes and their public keys, and both clients
compare that against the pinned copy before sending anything.  **This is a diagnostic, not
a security control.**  The response is unauthenticated, so the check can only ever refuse —
it has no path to accepting a key.  What it buys is that a rotated key or a mistyped pin
fails once, at startup, saying what disagreed, instead of as an unexplained run of
`SecurityException: proof did not verify`.

Three states, and clients treat them alike:

| `modes` in the response | Meaning | Client behaviour |
|---|---|---|
| absent | Older server, or no verifiable mode configured | Log and proceed; the endpoint's `404` is the capability probe |
| present, mode listed | Authoritative for this server | Compare against the pin; **a mismatch is fatal** |
| present, mode absent | Server publishes a complete list and this mode is off | Fail before spending a round trip |

The config is fetched once per server and is **not** re-fetched after a `404`.  An operator
enabling a mode after client startup is a restart-to-fix condition; re-fetching on demand
would hand a server a way to make clients re-read their configuration.

### Rotating a verifiable-mode key

There is deliberately no ephemeral fallback for these keys, and rotating one is not
transparent: every client holding the old pin will refuse the new key at the cross-check.
Distribute the new public key to clients **before** switching the server's master key, or
accept an outage for clients that have not been updated.

### Rust

The Rust crate implements both the client and the server sides of all three modes, but has
no transport layer by design — no HTTP dependency, and wire encoding is the caller's.
`VoprfClient::new` and `PoprfClient::new` take the server public key as bytes, with the
same out-of-band requirement.

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
