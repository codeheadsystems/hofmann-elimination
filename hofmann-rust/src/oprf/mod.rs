//! RFC 9497 Oblivious Pseudorandom Function (OPRF) — base mode (mode 0).
//!
//! Provides [`OprfCipherSuite`] which bundles a [`GroupSpec`](crate::elliptic_curve::GroupSpec),
//! hash algorithm, and domain separation tags for a complete OPRF cipher suite.
//! Supported suites are enumerated by [`CurveHashSuite`].
//!
//! Key operations:
//! - **`derive_key_pair`** — deterministic server key derivation (RFC 9497 §3.2.1)
//! - **`finalize`** — client-side unblinding and output hashing (RFC 9497 §3.3.1)

mod cipher_suite;

pub use cipher_suite::{CurveHashSuite, OprfCipherSuite};
