//! Elliptic curve abstractions and implementations for RFC 9380 hash-to-curve.
//!
//! This module provides:
//!
//! - [`GroupSpec`] — A trait abstracting over cryptographic group operations
//!   (hash-to-group, scalar multiplication, serialization). Adding a new cipher
//!   suite only requires implementing this trait.
//! - [`WeierstrassGroupSpec`] — Implementation for NIST Weierstrass curves
//!   (P-256, P-384, P-521) using the RustCrypto ecosystem with compressed SEC1
//!   point encoding.
//! - [`Ristretto255GroupSpec`] — Implementation for ristretto255 (RFC 9496)
//!   using `curve25519-dalek` with 32-byte canonical encoding and little-endian
//!   scalars.
//! - [`ExpandMessageXmd`] — RFC 9380 §5.3.1 `expand_message_xmd` for
//!   domain-separated hash expansion.

mod expand_message_xmd;
mod group_spec;
mod ristretto255;
mod weierstrass;

pub use expand_message_xmd::ExpandMessageXmd;
pub use group_spec::GroupSpec;
pub use ristretto255::Ristretto255GroupSpec;
pub use weierstrass::{CurveType, WeierstrassGroupSpec};
