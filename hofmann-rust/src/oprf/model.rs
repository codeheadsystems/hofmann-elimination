//! Contexts and key material for the verifiable OPRF modes.

use crate::oprf::cipher_suite::OprfCipherSuite;
use crate::oprf::mode::OprfMode;
use crate::oprf::public_input;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A server's key material for one verifiable mode.
///
/// Carries the mode it was derived for, so a detail built for VOPRF handed to a
/// POPRF server is an error rather than a silently different function.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VerifiableProcessorDetail {
    /// The secret scalar, in the suite's canonical encoding.
    pub secret_key: Vec<u8>,
    /// The public key `pkS = skS * G`, serialized.
    #[zeroize(skip)]
    pub public_key: Vec<u8>,
    /// The keying-context label stamped on responses.
    #[zeroize(skip)]
    pub processor_identifier: String,
    /// The mode this key was derived for.
    #[zeroize(skip)]
    pub mode: OprfMode,
}

impl VerifiableProcessorDetail {
    /// Derives a detail from a seed, per RFC 9497 §3.2.1.
    ///
    /// Deriving from a seed rather than accepting a raw key makes the one-key-per-mode
    /// rule self-enforcing: the mode byte is in the `DeriveKeyPair` DST, so the
    /// same seed yields a different key in each mode and a caller cannot
    /// accidentally share one.
    pub fn derive_from_seed(
        suite: &OprfCipherSuite,
        seed: &[u8],
        key_info: &[u8],
        processor_identifier: &str,
    ) -> Result<Self, &'static str> {
        suite.assert_mode(&[OprfMode::Voprf, OprfMode::Poprf])?;
        let secret_key = suite.derive_key_pair(seed, key_info);
        Self::from_secret(suite, secret_key, processor_identifier)
    }

    /// Builds a detail from an existing secret scalar, computing the public key.
    ///
    /// The public key is computed rather than accepted, so the pair cannot be
    /// mismatched.
    pub fn from_secret(
        suite: &OprfCipherSuite,
        secret_key: Vec<u8>,
        processor_identifier: &str,
    ) -> Result<Self, &'static str> {
        suite.assert_mode(&[OprfMode::Voprf, OprfMode::Poprf])?;
        let group = suite.group_spec();
        if group.scalar_is_zero(&secret_key) {
            // Every evaluation under a zero key returns the identity element.
            return Err("secret key is congruent to zero");
        }
        let public_key = group.scalar_multiply_generator(&secret_key);
        Ok(Self {
            secret_key,
            public_key,
            processor_identifier: processor_identifier.to_string(),
            mode: suite.mode(),
        })
    }
}

/// Client state between blinding a batch and finalizing the server's response.
///
/// Zeroized on drop: it holds the blinding factors and a copy of the caller's
/// plaintext inputs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VoprfClientContext {
    /// The caller's inputs, copied.
    pub inputs: Vec<Vec<u8>>,
    /// The blinding factors, one per input.
    pub blinds: Vec<Vec<u8>>,
    /// The blinded elements to send, one per input.
    #[zeroize(skip)]
    pub blinded_elements: Vec<Vec<u8>>,
}

impl VoprfClientContext {
    /// The number of inputs in this batch.
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Whether the batch is empty. Always false in practice — blinding an empty
    /// batch is refused — but clippy asks for it alongside `len`.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// As [`VoprfClientContext`], plus the public input and the key it tweaks to.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PoprfClientContext {
    /// The caller's inputs, copied.
    pub inputs: Vec<Vec<u8>>,
    /// The blinding factors, one per input.
    pub blinds: Vec<Vec<u8>>,
    /// The blinded elements to send, one per input.
    #[zeroize(skip)]
    pub blinded_elements: Vec<Vec<u8>>,
    /// The public input. Public by definition, so not zeroized.
    #[zeroize(skip)]
    pub info: Vec<u8>,
    /// `m*G + pkS`, derived by the client. The proof is graded against this.
    #[zeroize(skip)]
    pub tweaked_key: Vec<u8>,
}

impl PoprfClientContext {
    /// The number of inputs in this batch.
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// Derives the client-side tweaked key `m*G + pkS` for a public input.
///
/// One multi-scalar operation rather than `add(m*G, pkS)`: the composed form has
/// to serialize `m*G`, which is the identity when `m` is zero and has no encoding
/// on the NIST curves, so it would report the identity result RFC 9497 §3.3.3
/// asks the client to detect as a malformed element instead.
pub(crate) fn tweaked_public_key(
    suite: &OprfCipherSuite,
    server_public_key: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let m = public_input::to_scalar(suite, info)?;
    let group = suite.group_spec();
    let one = {
        let mut scalar = vec![0u8; group.scalar_size()];
        // Canonical encoding of 1: little-endian for ristretto255, big-endian
        // for the NIST curves. Written through the group's own convention
        // rather than assumed.
        if suite.identifier().starts_with("ristretto255") {
            scalar[0] = 1;
        } else {
            let last = scalar.len() - 1;
            scalar[last] = 1;
        }
        scalar
    };
    group.linear_combination(&[&m, &one], &[&group.generator(), server_public_key])
}
