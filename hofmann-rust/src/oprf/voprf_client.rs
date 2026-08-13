//! RFC 9497 §3.3.2 VOPRF client.

use crate::oprf::cipher_suite::OprfCipherSuite;
use crate::oprf::mode::OprfMode;
use crate::oprf::model::VoprfClientContext;
use crate::oprf::proof::{verify_proof, DleqProof};

/// A VOPRF client, bound to the server public key it grades proofs against.
///
/// The key is supplied at construction and **never** taken from a response. A
/// proof graded against a key the same server supplied proves nothing: a server
/// able to choose both can produce a verifying pair for any key it likes, and
/// RFC 9497 §7.3 notes it can do so per-client, partitioning users into
/// individually identifiable buckets. The key must arrive out of band,
/// authenticated by something other than the channel carrying the proof.
pub struct VoprfClient<'a> {
    suite: &'a OprfCipherSuite,
    server_public_key: Vec<u8>,
}

impl<'a> VoprfClient<'a> {
    /// Creates a client for a VOPRF-mode suite and an out-of-band public key.
    pub fn new(suite: &'a OprfCipherSuite, server_public_key: &[u8]) -> Result<Self, &'static str> {
        suite.assert_mode(&[OprfMode::Voprf])?;
        // Validated once, here. A public key that is the identity, off-curve or
        // non-canonically encoded would otherwise fail every proof with no
        // indication of why.
        suite.group_spec().validate_element(server_public_key)?;
        Ok(Self {
            suite,
            server_public_key: server_public_key.to_vec(),
        })
    }

    /// Blinds a batch of inputs, all to be evaluated under one proof.
    pub fn blind_batch(
        &self,
        inputs: &[&[u8]],
        rng: &mut dyn rand_core::CryptoRng,
    ) -> Result<VoprfClientContext, &'static str> {
        if inputs.is_empty() {
            return Err("at least one input is required");
        }
        let group = self.suite.group_spec();
        let mut blinds = Vec::with_capacity(inputs.len());
        let mut blinded_elements = Vec::with_capacity(inputs.len());
        let mut copied = Vec::with_capacity(inputs.len());
        for input in inputs {
            let hashed = group.hash_to_group(input, self.suite.hash_to_group_dst());
            // RFC 9497 §3.3.2 Blind raises InvalidInputError here. Reachable only
            // for an input whose hash-to-group lands on the identity, which no
            // known input does, but the alternative is an evaluation independent
            // of the server key.
            group.validate_element(&hashed)?;
            let blind = group.random_scalar(rng);
            blinded_elements.push(group.scalar_multiply(&blind, &hashed)?);
            blinds.push(blind);
            copied.push(input.to_vec());
        }
        Ok(VoprfClientContext {
            inputs: copied,
            blinds,
            blinded_elements,
        })
    }

    /// Verifies the server's proof and, **only if it holds**, unblinds every
    /// element.
    ///
    /// The order is not an implementation detail: unblinding before verifying
    /// produces output indistinguishable from correct, which is precisely what
    /// this mode exists to prevent.
    ///
    /// Every failure past the length check returns the same error. A caller —
    /// and through it a remote party — must not be able to tell a bad encoding
    /// from a proof that simply did not verify.
    pub fn finalize_batch(
        &self,
        ctx: &VoprfClientContext,
        evaluated_elements: &[Vec<u8>],
        proof: &[u8],
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        if evaluated_elements.len() != ctx.len() {
            return Err("server returned a different number of evaluated elements than were sent");
        }
        let group = self.suite.group_spec();
        // Element validation happens before the proof and may report itself:
        // the batch came from the server, which already knows what it sent.
        for element in evaluated_elements {
            group.validate_element(element)?;
        }

        let parsed = DleqProof::deserialize(self.suite, proof).map_err(|_| PROOF_FAILED)?;
        if !verify_proof(
            self.suite,
            &self.server_public_key,
            &ctx.blinded_elements,
            evaluated_elements,
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
                    .finalize(input, blind, element)
                    .map_err(|_| PROOF_FAILED)?,
            );
        }
        Ok(out)
    }
}

/// One message for every proof-side failure, so none of them are distinguishable.
const PROOF_FAILED: &str =
    "VOPRF proof did not verify; the server did not evaluate with the committed key";
