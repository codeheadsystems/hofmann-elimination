use crate::opaque::config::OpaqueConfig;
use crate::opaque::config::NN;
use crate::opaque::internal::{opaque_ake, opaque_credentials, opaque_oprf};
use crate::opaque::model::*;

/// OPAQUE client public API.
///
/// Provides registration and authentication operations. Borrows an
/// [`OpaqueConfig`] for cipher suite and KSF parameters.
///
/// # Usage
///
/// ```no_run
/// # use hofmann_rfc::opaque::config::OpaqueConfig;
/// # use hofmann_rfc::opaque::OpaqueClient;
/// let config = OpaqueConfig::for_testing();
/// let client = OpaqueClient::new(&config);
/// let mut rng = rand::thread_rng();
///
/// // Registration
/// let reg_state = client.create_registration_request(b"password", &mut rng);
/// // ... send reg_state.request to server, get response ...
///
/// // Authentication
/// let auth_state = client.generate_ke1(b"password", &mut rng);
/// // ... send auth_state.ke1 to server, get KE2 ...
/// ```
pub struct OpaqueClient<'a> {
    config: &'a OpaqueConfig,
}

impl<'a> OpaqueClient<'a> {
    pub fn new(config: &'a OpaqueConfig) -> Self {
        Self { config }
    }

    // --- Registration ---

    /// Creates a registration request by blinding the password.
    pub fn create_registration_request(
        &self,
        password: &[u8],
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> ClientRegistrationState {
        opaque_credentials::create_registration_request(password, self.config, rng)
    }

    /// Finalizes registration given the server's response.
    pub fn finalize_registration(
        &self,
        state: &ClientRegistrationState,
        response: &RegistrationResponse,
        server_identity: Option<&[u8]>,
        client_identity: Option<&[u8]>,
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> RegistrationRecord {
        opaque_credentials::finalize_registration(
            state,
            response,
            server_identity,
            client_identity,
            self.config,
            rng,
        )
    }

    // --- Authentication ---

    /// Generates KE1 (first AKE message) by blinding the password and creating a client ephemeral key pair.
    pub fn generate_ke1(
        &self,
        password: &[u8],
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> ClientAuthState {
        let blind = self.config.cipher_suite().oprf_suite().random_scalar(rng);
        let seed = self.config.random_bytes(NN, rng);
        let client_nonce = self.config.random_bytes(NN, rng);
        self.generate_ke1_deterministic(password, &blind, &client_nonce, &seed)
    }

    /// Generates KE3 (final client authentication message) and produces session/export keys.
    pub fn generate_ke3(
        &self,
        state: &ClientAuthState,
        client_identity: Option<&[u8]>,
        server_identity: Option<&[u8]>,
        ke2: &KE2,
    ) -> Result<AuthResult, &'static str> {
        opaque_ake::generate_ke3(
            state,
            client_identity,
            server_identity,
            ke2,
            self.config.context(),
            self.config,
        )
    }

    // --- Deterministic API (for testing) ---

    /// Creates a registration request with a fixed blinding factor.
    pub fn create_registration_request_deterministic(
        &self,
        password: &[u8],
        blind: &[u8],
    ) -> ClientRegistrationState {
        opaque_credentials::create_registration_request_with_blind(password, blind, self.config)
    }

    /// Finalizes registration with a fixed envelope nonce.
    pub fn finalize_registration_deterministic(
        &self,
        state: &ClientRegistrationState,
        response: &RegistrationResponse,
        server_identity: Option<&[u8]>,
        client_identity: Option<&[u8]>,
        envelope_nonce: &[u8],
    ) -> RegistrationRecord {
        opaque_credentials::finalize_registration_with_nonce(
            state,
            response,
            server_identity,
            client_identity,
            self.config,
            envelope_nonce,
        )
    }

    /// Generates KE1 with fixed blind, client nonce, and AKE key seed.
    pub fn generate_ke1_deterministic(
        &self,
        password: &[u8],
        blind: &[u8],
        client_nonce: &[u8],
        client_ake_key_seed: &[u8],
    ) -> ClientAuthState {
        let blinded_element = opaque_oprf::blind(self.config.cipher_suite(), password, blind);
        let cred_req = CredentialRequest { blinded_element };

        let kp = self
            .config
            .cipher_suite()
            .derive_ake_key_pair(client_ake_key_seed);
        let client_ake_sk = kp.private_key;
        let client_ake_pk = kp.public_key;

        let ke1 = KE1 {
            credential_request: cred_req,
            client_nonce: client_nonce.to_vec(),
            client_ake_public_key: client_ake_pk,
        };

        ClientAuthState {
            blind: blind.to_vec(),
            password: password.to_vec(),
            ke1,
            client_ake_private_key: client_ake_sk,
        }
    }
}
