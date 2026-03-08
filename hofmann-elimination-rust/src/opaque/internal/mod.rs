//! Internal OPAQUE protocol building blocks.
//!
//! These modules implement the low-level operations from RFC 9807:
//! - [`opaque_oprf`] — OPRF blind / evaluate / finalize / derive key
//! - [`opaque_envelope`] — envelope Store and Recover (§3.3.1.1)
//! - [`opaque_credentials`] — registration and credential response flows
//! - [`opaque_ake`] — 3DH authenticated key exchange (KE2/KE3 generation)

pub mod opaque_ake;
pub mod opaque_credentials;
pub mod opaque_envelope;
pub mod opaque_oprf;
