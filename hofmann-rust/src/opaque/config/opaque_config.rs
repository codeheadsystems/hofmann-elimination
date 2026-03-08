use super::OpaqueCipherSuite;

/// Nonce length — suite-independent (always 32).
pub const NN: usize = 32;

/// Configuration for the OPAQUE-3DH protocol.
///
/// Bundles a cipher suite with optional Argon2id key stretching parameters
/// and a protocol context string. Constructors provide sensible defaults
/// for testing (`for_testing`) and production (`default_config`, `with_argon2id`).
pub struct OpaqueConfig {
    cipher_suite: OpaqueCipherSuite,
    argon2_memory: u32,
    argon2_iterations: u32,
    argon2_parallelism: u32,
    context: Vec<u8>,
    use_argon2: bool,
}

impl OpaqueConfig {
    /// Creates a test configuration with Identity KSF, P256-SHA256 suite.
    pub fn for_testing() -> Self {
        Self {
            cipher_suite: OpaqueCipherSuite::p256_sha256(),
            argon2_memory: 0,
            argon2_iterations: 0,
            argon2_parallelism: 0,
            context: b"OPAQUE-POC".to_vec(),
            use_argon2: false,
        }
    }

    /// Creates a test configuration for a given cipher suite with Identity KSF.
    pub fn for_testing_with_suite(suite: OpaqueCipherSuite) -> Self {
        Self {
            cipher_suite: suite,
            argon2_memory: 0,
            argon2_iterations: 0,
            argon2_parallelism: 0,
            context: b"OPAQUE-POC".to_vec(),
            use_argon2: false,
        }
    }

    /// Default production configuration: Argon2id(64MB, 3 iterations, 1 parallelism), P256-SHA256.
    pub fn default_config() -> Self {
        Self {
            cipher_suite: OpaqueCipherSuite::p256_sha256(),
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            context: b"OPAQUE-3DH".to_vec(),
            use_argon2: true,
        }
    }

    /// Creates a configuration with Argon2id KSF and specified suite.
    pub fn with_argon2id(
        suite: OpaqueCipherSuite,
        context: Vec<u8>,
        memory: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Self {
        Self {
            cipher_suite: suite,
            argon2_memory: memory,
            argon2_iterations: iterations,
            argon2_parallelism: parallelism,
            context,
            use_argon2: true,
        }
    }

    // --- Accessors ---

    pub fn cipher_suite(&self) -> &OpaqueCipherSuite {
        &self.cipher_suite
    }

    pub fn context(&self) -> &[u8] {
        &self.context
    }

    pub fn nm(&self) -> usize {
        self.cipher_suite.nm()
    }
    pub fn nh(&self) -> usize {
        self.cipher_suite.nh()
    }
    pub fn nx(&self) -> usize {
        self.cipher_suite.nx()
    }
    pub fn npk(&self) -> usize {
        self.cipher_suite.npk()
    }
    pub fn nsk(&self) -> usize {
        self.cipher_suite.nsk()
    }
    pub fn noe(&self) -> usize {
        self.cipher_suite.noe()
    }
    pub fn nok(&self) -> usize {
        self.cipher_suite.nok()
    }
    pub fn envelope_size(&self) -> usize {
        self.cipher_suite.envelope_size()
    }
    pub fn masked_response_size(&self) -> usize {
        self.cipher_suite.masked_response_size()
    }

    /// Applies the key stretching function to the input.
    pub fn stretch_password(&self, input: &[u8]) -> Vec<u8> {
        if self.use_argon2 {
            use argon2::Argon2;

            let salt = [0u8; NN];
            let params = argon2::Params::new(
                self.argon2_memory,
                self.argon2_iterations,
                self.argon2_parallelism,
                Some(self.nh()),
            )
            .expect("invalid Argon2 params");

            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut output = vec![0u8; self.nh()];
            argon2
                .hash_password_into(input, &salt, &mut output)
                .expect("Argon2id failed");
            output
        } else {
            // Identity KSF
            input.to_vec()
        }
    }

    /// Generate random bytes.
    pub fn random_bytes(&self, len: usize, rng: &mut dyn rand_core::CryptoRngCore) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf
    }
}
