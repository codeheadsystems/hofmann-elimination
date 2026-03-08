//! RFC 9807 OPAQUE-3DH asymmetric PAKE protocol.
//!
//! OPAQUE allows a client to authenticate to a server using a password without
//! the server ever learning the password. The protocol has two phases:
//!
//! 1. **Registration** — client registers a password; server stores an
//!    [`RegistrationRecord`](model::RegistrationRecord) (no plaintext password).
//! 2. **Authentication** — three-message AKE (KE1 → KE2 → KE3) producing a
//!    shared session key.
//!
//! # Entry points
//!
//! - [`OpaqueClient`] — client-side registration and authentication
//! - [`OpaqueServer`] — server-side registration, authentication, and fake KE2
//!   generation for user enumeration protection
//! - [`config`] — cipher suite selection, key stretching, protocol configuration
//! - [`model`] — protocol message types (KE1, KE2, KE3, Envelope, etc.)

mod client;
pub mod config;
pub mod internal;
pub mod model;
mod server;

pub use client::OpaqueClient;
pub use server::OpaqueServer;
