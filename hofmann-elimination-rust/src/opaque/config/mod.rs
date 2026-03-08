//! OPAQUE protocol configuration: cipher suite selection, size constants, and
//! key stretching.
//!
//! - [`OpaqueCipherSuite`] wraps an [`OprfCipherSuite`](crate::oprf::OprfCipherSuite)
//!   with OPAQUE-specific size constants and HKDF operations.
//! - [`OpaqueConfig`] bundles a cipher suite with Argon2id parameters and a
//!   protocol context string.
//! - [`NN`] is the suite-independent nonce length (always 32 bytes).

mod opaque_cipher_suite;
mod opaque_config;

pub use opaque_cipher_suite::{AkeKeyPair, OpaqueCipherSuite};
pub use opaque_config::{Argon2idKsf, IdentityKsf, KeyStretchingFunction, OpaqueConfig, NN};
