//! # hofmann-rfc
//!
//! Rust implementation of three layered IETF RFCs for password-authenticated
//! key exchange:
//!
//! - **RFC 9380** — Hash-to-Elliptic-Curves (Simplified SWU, `expand_message_xmd`)
//! - **RFC 9497** — Oblivious Pseudorandom Functions (OPRF), base mode
//! - **RFC 9807** — OPAQUE asymmetric PAKE protocol
//!
//! ## Supported Cipher Suites
//!
//! | Suite | Curve | Hash | Element Size | Scalar Size | Hash Output |
//! |---|---|---|---|---|---|
//! | P256-SHA256 | NIST P-256 | SHA-256 | 33 bytes | 32 bytes | 32 bytes |
//! | P384-SHA384 | NIST P-384 | SHA-384 | 49 bytes | 48 bytes | 48 bytes |
//! | P521-SHA512 | NIST P-521 | SHA-512 | 67 bytes | 66 bytes | 64 bytes |
//! | ristretto255-SHA512 | ristretto255 | SHA-512 | 32 bytes | 32 bytes | 64 bytes |
//!
//! ## Quick Start: OPAQUE Registration + Authentication
//!
//! ```rust
//! use hofmann_rfc::opaque::config::OpaqueConfig;
//! use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};
//!
//! let config = OpaqueConfig::for_testing();
//! let mut rng = rand::thread_rng();
//!
//! // --- Server setup ---
//! let server = OpaqueServer::generate(&config, &mut rng);
//! let client = OpaqueClient::new(&config);
//!
//! // --- Registration ---
//! let reg_state = client.create_registration_request(b"password", &mut rng);
//! let reg_response = server
//!     .create_registration_response(&reg_state.request, b"user@example.com")
//!     .unwrap();
//! let record = client
//!     .finalize_registration(&reg_state, &reg_response, None, None, &mut rng)
//!     .unwrap();
//!
//! // --- Authentication ---
//! let auth_state = client.generate_ke1(b"password", &mut rng);
//! let ke2_result = server.generate_ke2(
//!     None, &record, b"user@example.com", &auth_state.ke1, None, &mut rng,
//! ).unwrap();
//! let auth_result = client.generate_ke3(&auth_state, None, None, &ke2_result.ke2).unwrap();
//! let session_key = server.server_finish(&ke2_result.server_auth_state, &auth_result.ke3).unwrap();
//!
//! assert_eq!(auth_result.session_key, session_key);
//! ```
//!
//! ## Module Organization
//!
//! - [`common`] — Byte-level utilities (I2OSP, concat, XOR, constant-time equality)
//! - [`elliptic_curve`] — [`GroupSpec`](elliptic_curve::GroupSpec) trait and curve implementations
//! - [`oprf`] — RFC 9497 OPRF cipher suite ([`OprfCipherSuite`](oprf::OprfCipherSuite))
//! - [`opaque`] — RFC 9807 OPAQUE protocol ([`OpaqueClient`](opaque::OpaqueClient),
//!   [`OpaqueServer`](opaque::OpaqueServer))
//!
//! ## Security
//!
//! This library has **not** been formally audited. Use at your own risk in
//! production systems. All MAC comparisons use constant-time equality, and
//! sensitive state (`ClientAuthState`, `ClientRegistrationState`,
//! `ServerAuthState`, `AuthResult`, `RegistrationRecord`) is zeroized on drop.

pub mod common;
pub mod elliptic_curve;
pub mod opaque;
pub mod oprf;
pub mod recovery;
