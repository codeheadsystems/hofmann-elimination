//! RFC 9497 §3.3.2 VOPRF server.

use crate::oprf::cipher_suite::OprfCipherSuite;
use crate::oprf::mode::OprfMode;
use crate::oprf::model::VerifiableProcessorDetail;
use crate::oprf::proof::generate_proof;

/// Default cap on how many elements one request may carry.
///
/// Not a cryptographic bound — batch proofs are sound at any size. It is a
/// resource bound: each element costs the server a scalar multiplication plus
/// its share of the proof, and the client chooses the count.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 64;

/// Ceiling on the configurable cap.
pub const ABSOLUTE_MAX_BATCH_SIZE: usize = 1024;

/// A VOPRF server: evaluates blinded elements and proves it used its committed key.
pub struct VoprfServer<'a> {
    suite: &'a OprfCipherSuite,
    detail: VerifiableProcessorDetail,
    max_batch_size: usize,
}

impl<'a> VoprfServer<'a> {
    /// Creates a server with the default batch cap.
    pub fn new(
        suite: &'a OprfCipherSuite,
        detail: VerifiableProcessorDetail,
    ) -> Result<Self, &'static str> {
        Self::with_max_batch_size(suite, detail, DEFAULT_MAX_BATCH_SIZE)
    }

    /// Creates a server with an explicit batch cap.
    pub fn with_max_batch_size(
        suite: &'a OprfCipherSuite,
        detail: VerifiableProcessorDetail,
        max_batch_size: usize,
    ) -> Result<Self, &'static str> {
        suite.assert_mode(&[OprfMode::Voprf])?;
        // One key must not serve two modes; a detail derived for POPRF computes
        // a different function under this suite's tags.
        if detail.mode != OprfMode::Voprf {
            return Err("processor detail was derived for a different mode");
        }
        if max_batch_size == 0 || max_batch_size > ABSOLUTE_MAX_BATCH_SIZE {
            return Err("max batch size must be between 1 and ABSOLUTE_MAX_BATCH_SIZE");
        }
        Ok(Self {
            suite,
            detail,
            max_batch_size,
        })
    }

    /// The public key clients grade this server's proofs against.
    pub fn public_key(&self) -> &[u8] {
        &self.detail.public_key
    }

    /// The keying-context label this server stamps on responses.
    pub fn processor_identifier(&self) -> &str {
        &self.detail.processor_identifier
    }

    /// Evaluates every blinded element and returns them with one proof covering
    /// the batch.
    ///
    /// Returns `(evaluated_elements, serialized_proof)`.
    pub fn evaluate_batch(
        &self,
        blinded_elements: &[Vec<u8>],
        rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<(Vec<Vec<u8>>, Vec<u8>), &'static str> {
        if blinded_elements.is_empty() {
            return Err("batch must contain at least one element");
        }
        if blinded_elements.len() > self.max_batch_size {
            return Err("batch exceeds the configured maximum");
        }
        let group = self.suite.group_spec();

        let mut evaluated = Vec::with_capacity(blinded_elements.len());
        for element in blinded_elements {
            // Validated before evaluation. Beyond hygiene: the proof transcript
            // hashes these exact bytes, so evaluating a re-encoded element would
            // produce a proof the client cannot verify against what it sent.
            group.validate_element(element)?;
            evaluated.push(group.scalar_multiply(&self.detail.secret_key, element)?);
        }

        let proof = generate_proof(
            self.suite,
            &self.detail.secret_key,
            &self.detail.public_key,
            blinded_elements,
            &evaluated,
            rng,
        )?;
        Ok((evaluated, proof.serialize(self.suite)))
    }
}
