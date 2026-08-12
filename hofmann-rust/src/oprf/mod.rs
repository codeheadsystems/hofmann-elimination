//! RFC 9497 Oblivious Pseudorandom Function (OPRF), in all three modes:
//! base (0x00), VOPRF (0x01) and POPRF (0x02).
//!
//! Provides [`OprfCipherSuite`] which bundles a [`GroupSpec`](crate::elliptic_curve::GroupSpec),
//! hash algorithm, and domain separation tags for a complete OPRF cipher suite.
//! Supported suites are enumerated by [`CurveHashSuite`], and the mode is chosen
//! with [`OprfCipherSuite::new_with_mode`] — [`OprfCipherSuite::new`] stays base
//! mode, which is what OPAQUE uses.
//!
//! Key operations:
//! - **`derive_key_pair`** — deterministic server key derivation (RFC 9497 §3.2.1)
//! - **`finalize`** — client-side unblinding and output hashing (RFC 9497 §3.3.1)
//! - **`finalize_with_info`** — the POPRF variant, which frames the public input
//!
//! # No transport, by design
//!
//! Like the rest of this crate, the verifiable modes are protocol crypto only:
//! the managers take and return byte slices, and there is no HTTP dependency.
//! Wire encoding and endpoints belong to the caller. The Java and TypeScript
//! ports have HTTP clients for `/oprf/verifiable` and
//! `/oprf/partially-oblivious` if a worked example is useful.
//!
//! # One key per mode
//!
//! The mode byte is in every domain-separation tag, so one secret serving two
//! modes computes two different functions under two different tag sets. RFC 9497
//! §7.2.3's static Diffie-Hellman budget is per-key, and POPRF exposes an
//! inversion oracle where the other modes expose a multiplication one. Derive a
//! separate key for each mode you enable.

mod cipher_suite;
mod mode;
mod model;
mod poprf_client;
mod poprf_server;
mod proof;
mod public_input;
mod voprf_client;
mod voprf_server;

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod vector_tests;

pub use cipher_suite::{CurveHashSuite, OprfCipherSuite};
pub use mode::OprfMode;
pub use model::{PoprfClientContext, VerifiableProcessorDetail, VoprfClientContext};
pub use poprf_client::PoprfClient;
pub use poprf_server::PoprfServer;
pub use proof::{DleqProof, MAX_BATCH};
pub use voprf_client::VoprfClient;
pub use voprf_server::{VoprfServer, ABSOLUTE_MAX_BATCH_SIZE, DEFAULT_MAX_BATCH_SIZE};
