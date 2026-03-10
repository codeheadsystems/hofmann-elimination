//! Account recovery support for OPAQUE.
//!
//! Because OPAQUE never exposes the password to the server, "password reset" is
//! not possible. Instead, account recovery is **verified re-registration**: the
//! user proves their identity through an out-of-band mechanism (email code, SMS
//! OTP, TOTP, etc.) and then re-registers with a new password using the standard
//! OPAQUE registration protocol.
//!
//! This module provides the building blocks:
//!
//! - [`RecoveryChallenger`] — trait you implement to send/verify challenges
//! - [`RecoveryTokenStore`] — trait for storing single-use recovery tokens
//! - [`InMemoryRecoveryTokenStore`] — default in-memory implementation
//!
//! The OPAQUE protocol layer is completely untouched by recovery. Recovery is
//! purely a server-side authorization mechanism that gates access to the existing
//! registration flow.
//!
//! # Flow
//!
//! 1. Client calls recovery start → server sends challenge via [`RecoveryChallenger::send_challenge`]
//! 2. Client submits challenge response → server verifies via [`RecoveryChallenger::verify_response`]
//! 3. On success, server stores a recovery token in [`RecoveryTokenStore`]
//! 4. Client uses the recovery token to authorize re-registration via standard
//!    OPAQUE registration endpoints
//! 5. On registration finish, the old credential is deleted and the token is consumed
//!
//! See `RECOVERY.md` in the project root for the full implementation guide.

mod challenger;
mod token_store;

pub use challenger::RecoveryChallenger;
pub use token_store::{InMemoryRecoveryTokenStore, RecoveryTokenStore};
