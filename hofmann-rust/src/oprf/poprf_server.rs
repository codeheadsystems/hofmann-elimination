//! RFC 9497 §3.3.3 POPRF server.

use crate::oprf::cipher_suite::OprfCipherSuite;
use crate::oprf::mode::OprfMode;
use crate::oprf::model::VerifiableProcessorDetail;
use crate::oprf::proof::generate_proof;
use crate::oprf::public_input;
use crate::oprf::voprf_server::{ABSOLUTE_MAX_BATCH_SIZE, DEFAULT_MAX_BATCH_SIZE};

/// A POPRF server: evaluates under a key tweaked by the request's public input.
pub struct PoprfServer<'a> {
    suite: &'a OprfCipherSuite,
    detail: VerifiableProcessorDetail,
    max_batch_size: usize,
}

impl<'a> PoprfServer<'a> {
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
        suite.assert_mode(&[OprfMode::Poprf])?;
        if detail.mode != OprfMode::Poprf {
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

    /// The server's **untweaked** public key, which is what clients pin.
    ///
    /// Never a tweaked key: the tweak is a function of `info`, which the client
    /// chooses, so a tweaked key would be the answer to one public input and
    /// wrong for every other.
    pub fn public_key(&self) -> &[u8] {
        &self.detail.public_key
    }

    /// The keying-context label this server stamps on responses.
    pub fn processor_identifier(&self) -> &str {
        &self.detail.processor_identifier
    }

    /// Evaluates a batch under the key tweaked by `info`, returning
    /// `(evaluated_elements, serialized_proof)`.
    pub fn evaluate_batch(
        &self,
        blinded_elements: &[Vec<u8>],
        info: &[u8],
        rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<(Vec<Vec<u8>>, Vec<u8>), &'static str> {
        if blinded_elements.is_empty() {
            return Err("batch must contain at least one element");
        }
        if blinded_elements.len() > self.max_batch_size {
            return Err("batch exceeds the configured maximum");
        }
        public_input::validate(info)?;
        let group = self.suite.group_spec();

        let m = public_input::to_scalar(self.suite, info)?;
        let t = group.scalar_add(&self.detail.secret_key, &m);
        if group.scalar_is_zero(&t) {
            // Requires m == -skS, which an attacker cannot search for without
            // the key. Refused rather than inverted, since there is no inverse.
            return Err("tweaked key is zero for this public input");
        }
        // B = t*G, recomputed per request rather than taken from the detail:
        // the proof is graded against the tweaked key, not the raw one.
        let tweaked_public_key = group.scalar_multiply_generator(&t);
        let t_inverse = group.scalar_inverse(&t);

        let mut evaluated = Vec::with_capacity(blinded_elements.len());
        for element in blinded_elements {
            group.validate_element(element)?;
            // The POPRF asymmetry: evaluated = t^-1 * blinded, where VOPRF
            // multiplies. This is why the prover sees the lists reversed.
            evaluated.push(group.scalar_multiply(&t_inverse, element)?);
        }

        let proof = generate_proof(
            self.suite,
            &t,
            &tweaked_public_key,
            &evaluated,
            blinded_elements,
            rng,
        )?;
        Ok((evaluated, proof.serialize(self.suite)))
    }
}
