use crate::common::{concat, ct_eq};
use crate::opaque::config::OpaqueConfig;
use crate::opaque::config::NN;
use crate::opaque::internal::{opaque_ake, opaque_credentials};
use crate::opaque::model::*;

/// OPAQUE server public API.
///
/// Holds the server's long-term DH key pair and OPRF seed. Provides
/// registration, authentication, and fake KE2 generation (for user
/// enumeration protection).
///
/// Use [`OpaqueServer::generate`] to create a new server with random keys,
/// or [`OpaqueServer::new`] with pre-existing key material.
pub struct OpaqueServer<'a> {
    server_private_key: Vec<u8>,
    server_public_key: Vec<u8>,
    oprf_seed: Vec<u8>,
    config: &'a OpaqueConfig,
}

impl<'a> OpaqueServer<'a> {
    /// Constructs a server with explicit key material.
    pub fn new(
        server_private_key: Vec<u8>,
        server_public_key: Vec<u8>,
        oprf_seed: Vec<u8>,
        config: &'a OpaqueConfig,
    ) -> Self {
        Self {
            server_private_key,
            server_public_key,
            oprf_seed,
            config,
        }
    }

    /// Generates a new server with a random key pair and OPRF seed.
    pub fn generate(config: &'a OpaqueConfig, rng: &mut dyn rand_core::CryptoRngCore) -> Self {
        let sk = config.cipher_suite().oprf_suite().random_scalar(rng);
        let pk = config
            .cipher_suite()
            .oprf_suite()
            .group_spec()
            .scalar_multiply_generator(&sk);
        let mut seed = vec![0u8; config.nok()];
        rng.fill_bytes(&mut seed);

        Self {
            server_private_key: sk,
            server_public_key: pk,
            oprf_seed: seed,
            config,
        }
    }

    pub fn server_public_key(&self) -> &[u8] {
        &self.server_public_key
    }

    pub fn server_private_key(&self) -> &[u8] {
        &self.server_private_key
    }

    pub fn oprf_seed(&self) -> &[u8] {
        &self.oprf_seed
    }

    // --- Registration ---

    /// Creates a registration response: evaluates the OPRF and returns the server's public key.
    pub fn create_registration_response(
        &self,
        request: &RegistrationRequest,
        credential_identifier: &[u8],
    ) -> RegistrationResponse {
        opaque_credentials::create_registration_response(
            self.config,
            request,
            &self.server_public_key,
            credential_identifier,
            &self.oprf_seed,
        )
    }

    // --- Authentication ---

    /// Generates KE2: evaluates OPRF, masks credentials, performs server-side AKE.
    pub fn generate_ke2(
        &self,
        server_identity: Option<&[u8]>,
        record: &RegistrationRecord,
        credential_identifier: &[u8],
        ke1: &KE1,
        client_identity: Option<&[u8]>,
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> ServerKE2Result {
        opaque_ake::generate_ke2(
            self.config,
            server_identity,
            &self.server_private_key,
            &self.server_public_key,
            record,
            credential_identifier,
            &self.oprf_seed,
            ke1,
            client_identity,
            rng,
        )
    }

    /// Finalizes server-side authentication: verifies the client MAC and returns the session key.
    pub fn server_finish(
        &self,
        state: &ServerAuthState,
        ke3: &KE3,
    ) -> Result<Vec<u8>, &'static str> {
        if !ct_eq(&state.expected_client_mac, &ke3.client_mac) {
            return Err("Authentication failed");
        }
        Ok(state.session_key.clone())
    }

    // --- Fake KE2 (user enumeration protection) ---

    /// Generates a fake KE2 for an unregistered credential identifier.
    pub fn generate_fake_ke2(
        &self,
        ke1: &KE1,
        credential_identifier: &[u8],
        server_identity: Option<&[u8]>,
        client_identity: Option<&[u8]>,
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> ServerKE2Result {
        let fake_record = self.create_fake_record(credential_identifier);
        opaque_ake::generate_ke2(
            self.config,
            server_identity,
            &self.server_private_key,
            &self.server_public_key,
            &fake_record,
            credential_identifier,
            &self.oprf_seed,
            ke1,
            client_identity,
            rng,
        )
    }

    fn create_fake_record(&self, credential_identifier: &[u8]) -> RegistrationRecord {
        let suite = self.config.cipher_suite();

        let fake_client_sk_seed = suite.hkdf_expand(
            &self.oprf_seed,
            &concat(&[credential_identifier, b"FakeClientKey"]),
            self.config.nsk(),
        );
        let fake_kp = suite.derive_ake_key_pair(&fake_client_sk_seed);
        let fake_client_pk = fake_kp.public_key;

        let fake_masking_key = suite.hkdf_expand(
            &self.oprf_seed,
            &concat(&[credential_identifier, b"FakeMaskingKey"]),
            self.config.nh(),
        );

        let fake_envelope = Envelope {
            envelope_nonce: vec![0u8; NN],
            auth_tag: vec![0u8; self.config.nm()],
        };

        RegistrationRecord {
            client_public_key: fake_client_pk,
            masking_key: fake_masking_key,
            envelope: fake_envelope,
        }
    }

    // --- Deterministic API (for testing) ---

    /// Generates KE2 with deterministic nonces and seeds.
    pub fn generate_ke2_deterministic(
        &self,
        server_identity: Option<&[u8]>,
        record: &RegistrationRecord,
        credential_identifier: &[u8],
        ke1: &KE1,
        client_identity: Option<&[u8]>,
        masking_nonce: &[u8],
        server_ake_key_seed: &[u8],
        server_nonce: &[u8],
    ) -> ServerKE2Result {
        opaque_ake::generate_ke2_deterministic(
            self.config,
            server_identity,
            &self.server_private_key,
            &self.server_public_key,
            record,
            credential_identifier,
            &self.oprf_seed,
            ke1,
            client_identity,
            masking_nonce,
            server_ake_key_seed,
            server_nonce,
        )
    }
}
