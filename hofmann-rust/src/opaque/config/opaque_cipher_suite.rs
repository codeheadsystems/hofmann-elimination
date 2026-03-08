use crate::common::{concat, i2osp};
use crate::oprf::{CurveHashSuite, OprfCipherSuite};

/// OPAQUE-specific cipher suite wrapper over an [`OprfCipherSuite`].
///
/// Provides OPAQUE protocol size constants (Npk, Nsk, Nh, Nm, Nx, Noe, Nok, Nn)
/// derived from the underlying suite, plus HKDF-Extract, HKDF-Expand, and
/// HKDF-Expand-Label operations used throughout the OPAQUE protocol.
///
/// # Size constants
///
/// | Suite | Npk | Nsk | Nh | Nn |
/// |---|---|---|---|---|
/// | P256-SHA256 | 33 | 32 | 32 | 32 |
/// | P384-SHA384 | 49 | 48 | 48 | 32 |
/// | P521-SHA512 | 67 | 66 | 64 | 32 |
/// | ristretto255-SHA512 | 32 | 32 | 64 | 32 |
pub struct OpaqueCipherSuite {
    oprf_suite: OprfCipherSuite,
    curve_hash_suite: CurveHashSuite,
}

/// A derived AKE key pair.
pub struct AkeKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl OpaqueCipherSuite {
    pub fn p256_sha256() -> Self {
        Self {
            oprf_suite: OprfCipherSuite::new(CurveHashSuite::P256Sha256),
            curve_hash_suite: CurveHashSuite::P256Sha256,
        }
    }

    pub fn p384_sha384() -> Self {
        Self {
            oprf_suite: OprfCipherSuite::new(CurveHashSuite::P384Sha384),
            curve_hash_suite: CurveHashSuite::P384Sha384,
        }
    }

    pub fn p521_sha512() -> Self {
        Self {
            oprf_suite: OprfCipherSuite::new(CurveHashSuite::P521Sha512),
            curve_hash_suite: CurveHashSuite::P521Sha512,
        }
    }

    pub fn ristretto255_sha512() -> Self {
        Self {
            oprf_suite: OprfCipherSuite::new(CurveHashSuite::Ristretto255Sha512),
            curve_hash_suite: CurveHashSuite::Ristretto255Sha512,
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name {
            "P256_SHA256" => Self::p256_sha256(),
            "P384_SHA384" => Self::p384_sha384(),
            "P521_SHA512" => Self::p521_sha512(),
            "RISTRETTO255_SHA512" => Self::ristretto255_sha512(),
            _ => panic!("Unknown OPAQUE cipher suite: {}", name),
        }
    }

    pub fn name(&self) -> &'static str {
        self.curve_hash_suite.name()
    }

    pub fn oprf_suite(&self) -> &OprfCipherSuite {
        &self.oprf_suite
    }

    /// Compressed public key size in bytes (33, 49, or 67).
    pub fn npk(&self) -> usize {
        self.oprf_suite.element_size()
    }

    /// Scalar (private key) size in bytes (32, 48, or 66).
    pub fn nsk(&self) -> usize {
        self.oprf_suite.group_spec().scalar_size()
    }

    /// Hash output length in bytes (32, 48, or 64).
    pub fn nh(&self) -> usize {
        self.oprf_suite.hash_output_length()
    }

    /// MAC output length = hash output length.
    pub fn nm(&self) -> usize {
        self.nh()
    }

    /// HKDF output length = hash output length.
    pub fn nx(&self) -> usize {
        self.nh()
    }

    /// OPRF evaluated element size = compressed public key size.
    pub fn noe(&self) -> usize {
        self.npk()
    }

    /// OPRF key size = scalar size.
    pub fn nok(&self) -> usize {
        self.nsk()
    }

    /// Nonce length — always 32, suite-independent.
    pub fn nn(&self) -> usize {
        32
    }

    /// Envelope size = Nn + Nm.
    pub fn envelope_size(&self) -> usize {
        self.nn() + self.nm()
    }

    /// Masked response size = Npk + envelope_size.
    pub fn masked_response_size(&self) -> usize {
        self.npk() + self.envelope_size()
    }

    // --- Cryptographic operations ---

    /// HKDF-Extract(salt, ikm) = HMAC-H(salt, ikm).
    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let actual_salt = if salt.is_empty() {
            vec![0u8; self.nh()]
        } else {
            salt.to_vec()
        };
        self.oprf_suite.hmac(&actual_salt, ikm)
    }

    /// HKDF-Expand(prk, info, len) per RFC 5869 §2.3.
    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let hash_len = self.nh();
        let mut result = Vec::with_capacity(len);
        let mut t: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;

        while result.len() < len {
            let input = concat(&[&t, info, &[counter]]);
            t = self.oprf_suite.hmac(prk, &input);
            let to_copy = std::cmp::min(len - result.len(), hash_len);
            result.extend_from_slice(&t[..to_copy]);
            counter += 1;
        }

        result
    }

    /// HKDF-Expand-Label(secret, label, context, length) in OPAQUE TLS-style format.
    pub fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let full_label = concat(&[b"OPAQUE-", label]);
        let info = concat(&[
            &i2osp(length as u32, 2),
            &i2osp(full_label.len() as u32, 1),
            &full_label,
            &i2osp(context.len() as u32, 1),
            context,
        ]);
        self.hkdf_expand(secret, &info, length)
    }

    /// HMAC-H(key, data).
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        self.oprf_suite.hmac(key, data)
    }

    /// H(data).
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        self.oprf_suite.hash(data)
    }

    /// Derives an AKE key pair from a seed.
    pub fn derive_ake_key_pair(&self, seed: &[u8]) -> AkeKeyPair {
        let sk = self
            .oprf_suite
            .derive_key_pair(seed, b"OPAQUE-DeriveDiffieHellmanKeyPair");
        let pk = self.oprf_suite.group_spec().scalar_multiply_generator(&sk);
        AkeKeyPair {
            private_key: sk,
            public_key: pk,
        }
    }
}
