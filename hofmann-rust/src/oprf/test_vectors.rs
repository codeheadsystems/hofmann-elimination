//! Loader for the RFC 9497 Appendix A test vectors. Test builds only.
//!
//! Reads `hofmann-rfc/src/test/resources/rfc9497/vectors.json` — the same file
//! the Java and TypeScript tests use, deliberately not a transcription of it.
//! Re-transcribing is how a port ends up testing a subset and passing: the file
//! already covers all four suites across all three modes, and a second copy
//! would drift.
//!
//! Embedded with `include_str!` so the tests do not depend on the working
//! directory, and parsed with `serde_json`, which is a dev-dependency — the
//! shipped crate has no serialization dependency.

use serde_json::Value;

const VECTORS_JSON: &str =
    include_str!("../../../hofmann-rfc/src/test/resources/rfc9497/vectors.json");

/// Which mode's vectors to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeName {
    /// Base mode (0x00).
    Oprf,
    /// Verifiable OPRF (0x01).
    Voprf,
    /// Partially-oblivious OPRF (0x02).
    Poprf,
}

impl ModeName {
    fn key(&self) -> &'static str {
        match self {
            ModeName::Oprf => "OPRF",
            ModeName::Voprf => "VOPRF",
            ModeName::Poprf => "POPRF",
        }
    }
}

/// One Appendix A vector, with the comma-separated batch fields split out.
///
/// **Every scalar stays as bytes.** The RFC prints scalars in each suite's own
/// canonical encoding — big-endian for the NIST curves, little-endian for
/// ristretto255 — so a loader that decoded them itself would have to reimplement
/// the convention the group spec exists to own, and would silently produce
/// garbage on one of the four suites.
pub struct Vector {
    /// The number of inputs in this vector's batch.
    pub batch_size: usize,
    /// The client inputs.
    pub inputs: Vec<Vec<u8>>,
    /// The blinding factors, in canonical scalar encoding.
    pub blinds: Vec<Vec<u8>>,
    /// The blinded elements.
    pub blinded_elements: Vec<Vec<u8>>,
    /// The server's evaluated elements.
    pub evaluation_elements: Vec<Vec<u8>>,
    /// The expected OPRF outputs.
    pub outputs: Vec<Vec<u8>>,
    /// The serialized DLEQ proof. Absent in base mode.
    pub proof: Option<Vec<u8>>,
    /// The fixed proof randomness. Absent in base mode.
    pub proof_random_scalar: Option<Vec<u8>>,
    /// The public input. POPRF only.
    pub info: Option<Vec<u8>>,
}

/// The vectors for one (suite, mode) pair.
pub struct ModeVectors {
    /// The server secret key, in canonical scalar encoding.
    pub sk_sm: Vec<u8>,
    /// The server public key. Absent in base mode.
    pub pk_sm: Option<Vec<u8>>,
    /// The key-derivation seed.
    pub seed: Vec<u8>,
    /// The key-derivation info.
    pub key_info: Vec<u8>,
    /// The vectors themselves.
    pub vectors: Vec<Vector>,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("vector field is not valid hex")
}

fn split_hex(value: &str) -> Vec<Vec<u8>> {
    value.split(',').map(unhex).collect()
}

fn field<'a>(node: &'a Value, name: &str) -> Option<&'a str> {
    node.get(name).and_then(|v| v.as_str())
}

/// Loads the vectors for one suite and mode.
///
/// `suite` is the RFC's spelling, e.g. `"P256-SHA256"`.
pub fn load(suite: &str, mode: ModeName) -> ModeVectors {
    let root: Value = serde_json::from_str(VECTORS_JSON).expect("vectors.json is not valid JSON");
    let node = root
        .get(suite)
        .and_then(|s| s.get(mode.key()))
        .unwrap_or_else(|| panic!("no vectors for {suite}/{:?}", mode));
    let keys = node.get("keys").expect("vector block has no keys");

    let vectors = node
        .get("vectors")
        .and_then(|v| v.as_array())
        .expect("vector block has no vectors")
        .iter()
        .map(|v| Vector {
            batch_size: v.get("batchSize").and_then(|b| b.as_u64()).unwrap_or(1) as usize,
            inputs: split_hex(field(v, "Input").expect("vector has no Input")),
            blinds: split_hex(field(v, "Blind").expect("vector has no Blind")),
            blinded_elements: split_hex(
                field(v, "BlindedElement").expect("vector has no BlindedElement"),
            ),
            evaluation_elements: split_hex(
                field(v, "EvaluationElement").expect("vector has no EvaluationElement"),
            ),
            outputs: split_hex(field(v, "Output").expect("vector has no Output")),
            proof: field(v, "Proof").map(unhex),
            proof_random_scalar: field(v, "ProofRandomScalar").map(unhex),
            info: field(v, "Info").map(unhex),
        })
        .collect();

    ModeVectors {
        sk_sm: unhex(field(keys, "skSm").expect("keys have no skSm")),
        pk_sm: field(keys, "pkSm").map(unhex),
        seed: unhex(field(keys, "Seed").expect("keys have no Seed")),
        key_info: unhex(field(keys, "KeyInfo").expect("keys have no KeyInfo")),
        vectors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_every_suite_and_mode() {
        for suite in [
            "P256-SHA256",
            "P384-SHA384",
            "P521-SHA512",
            "ristretto255-SHA512",
        ] {
            for mode in [ModeName::Oprf, ModeName::Voprf, ModeName::Poprf] {
                let v = load(suite, mode);
                assert!(!v.vectors.is_empty(), "{suite}/{mode:?} has no vectors");
                assert!(!v.sk_sm.is_empty());
                if mode != ModeName::Oprf {
                    assert!(v.vectors.iter().all(|x| x.proof.is_some()));
                }
                if mode == ModeName::Poprf {
                    assert!(v.vectors.iter().all(|x| x.info.is_some()));
                }
            }
        }
    }

    /// The batch fields are comma-separated, and a loader that ignored that
    /// would silently test only batch size 1.
    #[test]
    fn splits_batched_vectors() {
        let v = load("P256-SHA256", ModeName::Voprf);
        let batched = v
            .vectors
            .iter()
            .find(|x| x.batch_size == 2)
            .expect("no batch-size-2 vector");

        assert_eq!(batched.inputs.len(), 2);
        assert_eq!(batched.blinded_elements.len(), 2);
        assert_eq!(batched.outputs.len(), 2);
    }
}
