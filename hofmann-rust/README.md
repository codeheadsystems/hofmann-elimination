# hofmann-rfc

Rust implementation of three layered IETF RFCs for password-authenticated key exchange (PAKE):

- **RFC 9380** — Hash-to-Elliptic-Curves (Simplified SWU, `expand_message_xmd`)
- **RFC 9497** — Oblivious Pseudorandom Functions (OPRF), base mode (mode 0)
- **RFC 9807** — OPAQUE asymmetric PAKE protocol (OPAQUE-3DH)

OPAQUE allows a client to authenticate to a server using a password without the server ever learning the password. The server stores only a registration record derived from the password, and both parties arrive at a shared session key upon successful authentication.

## Supported Cipher Suites

| Suite | Curve | Hash | Element Size | Scalar Size | Hash Output |
|---|---|---|---|---|---|
| P256-SHA256 | NIST P-256 | SHA-256 | 33 bytes | 32 bytes | 32 bytes |
| P384-SHA384 | NIST P-384 | SHA-384 | 49 bytes | 48 bytes | 48 bytes |
| P521-SHA512 | NIST P-521 | SHA-512 | 67 bytes | 66 bytes | 64 bytes |
| ristretto255-SHA512 | ristretto255 | SHA-512 | 32 bytes | 32 bytes | 64 bytes |

## Quick Start

```rust
use hofmann_rfc::opaque::config::OpaqueConfig;
use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};

let config = OpaqueConfig::for_testing();
let mut rng = rand::rng();

// --- Server setup ---
let server = OpaqueServer::generate(&config, &mut rng);
let client = OpaqueClient::new(&config);

// --- Registration ---
let reg_state = client.create_registration_request(b"password", &mut rng);
let reg_response = server.create_registration_response(
    &reg_state.request, b"user@example.com",
);
let record = client.finalize_registration(
    &reg_state, &reg_response, None, None, &mut rng,
);

// --- Authentication ---
let auth_state = client.generate_ke1(b"password", &mut rng);
let ke2_result = server.generate_ke2(
    None, &record, b"user@example.com", &auth_state.ke1, None, &mut rng,
);
let auth_result = client.generate_ke3(
    &auth_state, None, None, &ke2_result.ke2,
).unwrap();
let session_key = server.server_finish(
    &ke2_result.server_auth_state, &auth_result.ke3,
).unwrap();

assert_eq!(auth_result.session_key, session_key);
```

## Module Organization

| Module | Description |
|---|---|
| `common` | Byte-level utilities: I2OSP (RFC 8017), concat, XOR, constant-time equality |
| `elliptic_curve` | `GroupSpec` trait and implementations for Weierstrass curves and ristretto255 |
| `oprf` | RFC 9497 OPRF cipher suite — `derive_key_pair`, `finalize`, hash/HMAC |
| `opaque` | RFC 9807 OPAQUE protocol — `OpaqueClient`, `OpaqueServer`, configuration, model types |

### Key Abstractions

- **`GroupSpec`** — Trait abstracting over cryptographic group operations (hash-to-group, scalar multiplication, serialization). Adding a new cipher suite only requires implementing this trait.
- **`OprfCipherSuite`** — Bundles a `GroupSpec` with hash algorithm and domain separation tags for a complete OPRF suite.
- **`OpaqueCipherSuite`** — Wraps `OprfCipherSuite` with OPAQUE-specific size constants and HKDF operations.
- **`OpaqueConfig`** — Protocol configuration: cipher suite, Argon2id KSF parameters, and context string.

## Key Stretching

The library supports Argon2id for password hardening between the OPRF output and key derivation. Use `OpaqueConfig::with_argon2id` or `OpaqueConfig::default_config` (64 MB, 3 iterations) for production. Use `OpaqueConfig::for_testing` (identity KSF) for test vectors and development.

## User Enumeration Protection

`OpaqueServer::generate_fake_ke2` produces a KE2 message for unregistered users that is indistinguishable from a real one, preventing attackers from determining whether a username exists.

## Building and Testing

```sh
cargo build
cargo test
cargo doc --open
```

## Dependencies

- **RustCrypto** (`p256`, `p384`, `p521`, `sha2`, `hmac`, `hkdf`) — Weierstrass curve arithmetic and hashing
- **curve25519-dalek** — ristretto255 group operations
- **argon2** — Argon2id key stretching
- **subtle** — Constant-time MAC comparison
- **zeroize** — Zeroing sensitive memory on drop

## Publishing to crates.io

Ensure the version in `Cargo.toml` is correct, then:

```sh
# Dry run — validates packaging without uploading
cargo publish --dry-run

# Publish (requires a crates.io API token configured via `cargo login`)
cargo publish
```

If publishing for the first time, log in with your API token from https://crates.io/settings/tokens:

```sh
cargo login
```

The `Cargo.toml` already includes the required metadata (`description`, `license`, `repository`, `keywords`, `categories`). After publishing, the crate will be available as:

```toml
[dependencies]
hofmann-rfc = "3.0.0"
```

## Security

This library has **not** been formally audited. Use at your own risk in production systems. Mitigations in place:

- All MAC comparisons use constant-time equality (`subtle` crate)
- Sensitive client state (`ClientAuthState`, `ClientRegistrationState`) is zeroized on drop
- Fake KE2 generation prevents user enumeration

## License

Apache-2.0
