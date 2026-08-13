//! RFC 9497 §3.3.3 POPRF client.

use crate::oprf::cipher_suite::OprfCipherSuite;
use crate::oprf::mode::OprfMode;
use crate::oprf::model::{tweaked_public_key, PoprfClientContext};
use crate::oprf::proof::{verify_proof, DleqProof};
use crate::oprf::public_input;

/// A POPRF client, bound to the server's **untweaked** public key.
///
/// As with VOPRF, the key is supplied at construction and never taken from a
/// response. The tweak is derived here from the public input the client chooses,
/// which is what binds a response to the question actually asked.
pub struct PoprfClient<'a> {
    suite: &'a OprfCipherSuite,
    server_public_key: Vec<u8>,
}

impl<'a> PoprfClient<'a> {
    /// Creates a client for a POPRF-mode suite and an out-of-band public key.
    pub fn new(suite: &'a OprfCipherSuite, server_public_key: &[u8]) -> Result<Self, &'static str> {
        suite.assert_mode(&[OprfMode::Poprf])?;
        suite.group_spec().validate_element(server_public_key)?;
        Ok(Self {
            suite,
            server_public_key: server_public_key.to_vec(),
        })
    }

    /// Blinds a batch under a public input.
    ///
    /// `info` is required and an empty slice is a valid value meaning "no public
    /// input" — an absent public input and an empty one are different public
    /// inputs producing different outputs, so there is no default.
    pub fn blind_batch(
        &self,
        inputs: &[&[u8]],
        info: &[u8],
        rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<PoprfClientContext, &'static str> {
        if inputs.is_empty() {
            return Err("at least one input is required");
        }
        public_input::validate(info)?;
        let group = self.suite.group_spec();
        let tweaked_key = tweaked_public_key(self.suite, &self.server_public_key, info)?;

        let mut blinds = Vec::with_capacity(inputs.len());
        let mut blinded_elements = Vec::with_capacity(inputs.len());
        let mut copied = Vec::with_capacity(inputs.len());
        for input in inputs {
            let hashed = group.hash_to_group(input, self.suite.hash_to_group_dst());
            group.validate_element(&hashed)?;
            let blind = group.random_scalar(rng);
            blinded_elements.push(group.scalar_multiply(&blind, &hashed)?);
            blinds.push(blind);
            copied.push(input.to_vec());
        }
        Ok(PoprfClientContext {
            inputs: copied,
            blinds,
            blinded_elements,
            info: info.to_vec(),
            tweaked_key,
        })
    }

    /// Verifies the proof and, only if it holds, unblinds every element.
    ///
    /// Graded against the client's own tweaked key, with the element lists in
    /// POPRF order — **evaluated first**, because `blindedElement = t *
    /// evaluatedElement`. A port that keeps VOPRF's order round-trips against
    /// itself and fails every RFC vector.
    pub fn finalize_batch(
        &self,
        ctx: &PoprfClientContext,
        evaluated_elements: &[Vec<u8>],
        proof: &[u8],
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        if evaluated_elements.len() != ctx.len() {
            return Err("server returned a different number of evaluated elements than were sent");
        }
        let group = self.suite.group_spec();
        for element in evaluated_elements {
            group.validate_element(element)?;
        }

        let parsed = DleqProof::deserialize(self.suite, proof).map_err(|_| PROOF_FAILED)?;
        if !verify_proof(
            self.suite,
            &ctx.tweaked_key,
            evaluated_elements,
            &ctx.blinded_elements,
            &parsed,
        ) {
            return Err(PROOF_FAILED);
        }

        let mut out = Vec::with_capacity(ctx.len());
        for ((input, blind), element) in ctx
            .inputs
            .iter()
            .zip(ctx.blinds.iter())
            .zip(evaluated_elements.iter())
        {
            out.push(
                self.suite
                    .finalize_with_info(input, &ctx.info, blind, element)
                    .map_err(|_| PROOF_FAILED)?,
            );
        }
        Ok(out)
    }
}

/// One message for every proof-side failure, so none of them are distinguishable.
const PROOF_FAILED: &str = "POPRF proof did not verify; the server did not evaluate with the \
                            committed key under this public input";
