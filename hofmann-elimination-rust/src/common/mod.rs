//! Byte-level utility functions shared across the crate.
//!
//! Provides RFC 8017 I2OSP encoding, byte array concatenation, XOR, and
//! constant-time comparison.

mod byte_utils;

pub use byte_utils::*;
