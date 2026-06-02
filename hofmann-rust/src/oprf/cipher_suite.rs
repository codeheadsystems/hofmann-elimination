use crate::common::{concat, i2osp};
use crate::elliptic_curve::{CurveType, GroupSpec, Ristretto255GroupSpec, WeierstrassGroupSpec};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::Arc;

/// Supported curve + hash combinations for RFC 9497 OPRF.
///
/// Each variant determines the elliptic curve group, hash function, and
/// all derived DST strings used by [`OprfCipherSuite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveHashSuite {
    /// P-256 with SHA-256 (Nh=32).
    P256Sha256,
    /// P-384 with SHA-384 (Nh=48).
    P384Sha384,
    /// P-521 with SHA-512 (Nh=64).
    P521Sha512,
    /// ristretto255 with SHA-512 (Nh=64).
    Ristretto255Sha512,
}

impl CurveHashSuite {
    pub fn from_name(name: &str) -> Self {
        match name {
            "P256_SHA256" => CurveHashSuite::P256Sha256,
            "P384_SHA384" => CurveHashSuite::P384Sha384,
            "P521_SHA512" => CurveHashSuite::P521Sha512,
            "RISTRETTO255_SHA512" => CurveHashSuite::Ristretto255Sha512,
            _ => panic!("Unknown suite: {}", name),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            CurveHashSuite::P256Sha256 => "P256_SHA256",
            CurveHashSuite::P384Sha384 => "P384_SHA384",
            CurveHashSuite::P521Sha512 => "P521_SHA512",
            CurveHashSuite::Ristretto255Sha512 => "RISTRETTO255_SHA512",
        }
    }
}

/// Hash algorithm used by an OPRF cipher suite.
#[derive(Debug, Clone, Copy)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Central cipher suite abstraction for RFC 9497 OPRF (base mode).
///
/// Bundles a [`GroupSpec`], hash algorithm, domain separation tags, and context
/// string. All OPRF operations (blind, evaluate, finalize, derive_key_pair)
/// are driven through this type.
///
/// The context string follows the format `"OPRFV1-\x00-{suite}"` per RFC 9497 §3.2.
pub struct OprfCipherSuite {
    identifier: String,
    context_string: Vec<u8>,
    hash_to_group_dst: Vec<u8>,
    hash_to_scalar_dst: Vec<u8>,
    derive_key_pair_dst: Vec<u8>,
    group_spec: Arc<dyn GroupSpec>,
    hash_algorithm: HashAlgorithm,
    hash_output_length: usize,
}

impl OprfCipherSuite {
    /// Creates a new OPRF cipher suite for the given curve+hash combination.
    pub fn new(suite: CurveHashSuite) -> Self {
        let (identifier, context_suffix, group_spec, hash_alg, hash_len): (
            &str,
            &str,
            Arc<dyn GroupSpec>,
            HashAlgorithm,
            usize,
        ) = match suite {
            CurveHashSuite::P256Sha256 => (
                "P256-SHA256",
                "P256-SHA256",
                Arc::new(WeierstrassGroupSpec::new(CurveType::P256)),
                HashAlgorithm::Sha256,
                32,
            ),
            CurveHashSuite::P384Sha384 => (
                "P384-SHA384",
                "P384-SHA384",
                Arc::new(WeierstrassGroupSpec::new(CurveType::P384)),
                HashAlgorithm::Sha384,
                48,
            ),
            CurveHashSuite::P521Sha512 => (
                "P521-SHA512",
                "P521-SHA512",
                Arc::new(WeierstrassGroupSpec::new(CurveType::P521)),
                HashAlgorithm::Sha512,
                64,
            ),
            CurveHashSuite::Ristretto255Sha512 => (
                "ristretto255-SHA512",
                "ristretto255-SHA512",
                Arc::new(Ristretto255GroupSpec),
                HashAlgorithm::Sha512,
                64,
            ),
        };

        let context_string = build_context_string(context_suffix);
        let hash_to_group_dst = concat(&[b"HashToGroup-", &context_string]);
        let hash_to_scalar_dst = concat(&[b"HashToScalar-", &context_string]);
        let derive_key_pair_dst = concat(&[b"DeriveKeyPair", &context_string]);

        Self {
            identifier: identifier.to_string(),
            context_string,
            hash_to_group_dst,
            hash_to_scalar_dst,
            derive_key_pair_dst,
            group_spec,
            hash_algorithm: hash_alg,
            hash_output_length: hash_len,
        }
    }

    // --- Accessors ---

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn context_string(&self) -> &[u8] {
        &self.context_string
    }

    pub fn hash_to_group_dst(&self) -> &[u8] {
        &self.hash_to_group_dst
    }

    pub fn hash_to_scalar_dst(&self) -> &[u8] {
        &self.hash_to_scalar_dst
    }

    pub fn derive_key_pair_dst(&self) -> &[u8] {
        &self.derive_key_pair_dst
    }

    pub fn group_spec(&self) -> &dyn GroupSpec {
        self.group_spec.as_ref()
    }

    pub fn hash_output_length(&self) -> usize {
        self.hash_output_length
    }

    pub fn element_size(&self) -> usize {
        self.group_spec.element_size()
    }

    // --- Random scalar ---

    pub fn random_scalar(&self, rng: &mut dyn rand_core::CryptoRngCore) -> Vec<u8> {
        self.group_spec.random_scalar(rng)
    }

    // --- Crypto operations ---

    /// Hashes input to a scalar modulo the group order (RFC 9497 §2.1).
    pub fn hash_to_scalar(&self, input: &[u8], dst: &[u8]) -> Vec<u8> {
        self.group_spec.hash_to_scalar(input, dst)
    }

    /// Derives a server private key from seed and info per RFC 9497 §3.2.1.
    pub fn derive_key_pair(&self, seed: &[u8], info: &[u8]) -> Vec<u8> {
        let derive_input = concat(&[seed, &i2osp(info.len() as u32, 2), info]);

        let mut counter: u16 = 0;
        loop {
            assert!(counter <= 255, "DeriveKeyPair: exceeded counter limit");
            let counter_input = concat(&[&derive_input, &i2osp(counter as u32, 1)]);
            let sk_s = self.hash_to_scalar(&counter_input, &self.derive_key_pair_dst);

            // Check if scalar is zero (all zero bytes)
            if sk_s.iter().any(|&b| b != 0) {
                return sk_s;
            }
            counter += 1;
        }
    }

    /// RFC 9497 §3.3.1 Finalize: unblind the evaluated element and produce the OPRF output.
    ///
    /// Returns `Err` if `evaluated_element` (supplied by the server) is not a
    /// valid non-identity group element, so a malicious or buggy server cannot
    /// panic the client or collapse the output to a key-independent value.
    pub fn finalize(
        &self,
        input: &[u8],
        blind: &[u8],
        evaluated_element: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let inverse_blind = self.group_spec.scalar_inverse(blind);
        let unblinded_element = self
            .group_spec
            .scalar_multiply(&inverse_blind, evaluated_element)?;

        let hash_input = concat(&[
            &i2osp(input.len() as u32, 2),
            input,
            &i2osp(unblinded_element.len() as u32, 2),
            &unblinded_element,
            b"Finalize",
        ]);

        Ok(self.hash(&hash_input))
    }

    /// Computes Hash(data) using the suite's hash algorithm.
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// Computes HMAC(key, data) using the suite's hash algorithm.
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self.hash_algorithm {
            HashAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length error");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("HMAC key length error");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC key length error");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn build_context_string(suffix: &str) -> Vec<u8> {
    // "OPRFV1-" + 0x00 + "-" + suffix
    concat(&[b"OPRFV1-", &[0x00], format!("-{}", suffix).as_bytes()])
}
