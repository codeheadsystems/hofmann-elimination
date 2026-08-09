# Documentation map

Every document in this repository, indexed by the question it answers. Start from the task, not
the filename.

## I want to run this

| Question | Document |
|---|---|
| What is this, and should I use it? | [README](../README.md), [PRFAQ](../PRFAQ.md) |
| What do I put in my server config, and what does each field cost me? | [Server configuration](../USAGE.md) |
| How do I generate the four secrets, and how do I rotate one? | [Key management](KEY_MANAGEMENT.md) |
| How do I wire this into Dropwizard, Spring Boot, or my own HTTP layer? | [Framework integration](INTEGRATION.md) |
| How do I persist credentials and sessions? | [Framework integration](INTEGRATION.md#implementing-credentialstore) |
| How do I configure the Java or TypeScript client? | [Client configuration](CLIENT_CONFIG.md) |
| Why does authentication fail after I set Argon2id parameters by hand? | [Client configuration](CLIENT_CONFIG.md#argon2id-consistency-between-server-and-client) |
| How do I move an existing password database onto OPAQUE? | [Migration guide](../MIGRATION.md) |
| How do users change a password, or recover an account? | [Change password](../CHANGE_PASSWORD.md), [Account recovery](../RECOVERY.md) |
| I want to try it locally | [Server configuration § Local test server](../USAGE.md#local-test-server), [demo](../hofmann-demo/README.md), [testserver](../hofmann-testserver/README.md) |

## I want to understand the security posture

| Question | Document |
|---|---|
| What is the threat model, and what is *not* covered? | [SECURITY.md](../SECURITY.md) |
| Why is this component built the way it is? | [Architecture decision records](adr/) |
| Which earlier analysis turned out to be wrong? | [ADR § Superseded analyses](adr/) — every record has one |
| What is still open? | [TODO.md](../TODO.md) |
| What changed, and when? | [CHANGELOG.md](../CHANGELOG.md) |

## I want to understand the cryptography

| Question | Document |
|---|---|
| How is OPAQUE (RFC 9807) implemented here? | [OPAQUE.md](../hofmann-rfc/OPAQUE.md) |
| How are the three OPRF modes (RFC 9497) implemented? | [OPRF.md](../hofmann-rfc/OPRF.md) |
| How does hash-to-curve (RFC 9380) work here? | [HASH_TO_CURVE.md](../hofmann-rfc/HASH_TO_CURVE.md) |
| Why was ristretto255 hard? | [ristretto255.md](../ristretto255.md) |

## I want to work on this repository

| Question | Document |
|---|---|
| How do I build it, and why must I run one build at a time? | [README § Building](../README.md#building), [ADR-0004](adr/0004-one-build-per-checkout.md) |
| How do I run the end-to-end tests across all three implementations? | [INTEGRATION_TEST.md](../INTEGRATION_TEST.md) |
| How do I cut a release? | [RELEASING.md](../RELEASING.md) |
| How do I record a decision I just made? | [ADR § Writing a new one](adr/README.md#writing-a-new-one) |

## Ports

| Implementation | Document |
|---|---|
| TypeScript / browser | [hofmann-typescript](../hofmann-typescript/README.md) |
| Rust | [hofmann-rust](../hofmann-rust/README.md) |

## API reference

- **[Interactive Swagger UI](https://codeheadsystems.github.io/hofmann-elimination/api-docs.html)**
- Raw OpenAPI: [OPAQUE](opaque-api.yaml) · [OPRF](oprf-api.yaml)
- The endpoint list with auth requirements is in
  [Server configuration](../USAGE.md#endpoints-registered-by-the-bundle).

## How these fit together

`USAGE.md` is the **reference** — fields, defaults, endpoints. The three documents in this
directory are the **procedures** that reference points at: generating and rotating keys,
configuring a client, wiring a framework. `SECURITY.md` is the **threat model** behind the
defaults, and `adr/` is **why** each load-bearing decision is shaped the way it is.

When one of these contradicts the source, the source wins and the document is a defect — see
`adr/0002` for a case where a stale sentence outlived its code by three days and told operators
to enable something already enabled.
