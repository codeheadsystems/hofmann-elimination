use crate::common::{concat, i2osp};
use crate::opaque::config::OpaqueConfig;
use crate::opaque::config::NN;
use zeroize::Zeroize;

/// Client's first AKE message.
#[derive(Clone, Debug)]
pub struct KE1 {
    pub credential_request: CredentialRequest,
    pub client_nonce: Vec<u8>,
    pub client_ake_public_key: Vec<u8>,
}

impl KE1 {
    pub fn serialize(&self) -> Vec<u8> {
        concat(&[
            &self.credential_request.blinded_element,
            &self.client_nonce,
            &self.client_ake_public_key,
        ])
    }
}

/// Server's AKE response.
#[derive(Clone, Debug)]
pub struct KE2 {
    pub credential_response: CredentialResponse,
    pub server_nonce: Vec<u8>,
    pub server_ake_public_key: Vec<u8>,
    pub server_mac: Vec<u8>,
}

impl KE2 {
    /// Deserialize from bytes using the config for size constants.
    pub fn deserialize(config: &OpaqueConfig, data: &[u8]) -> Self {
        let noe = config.noe();
        let nn = NN;
        let masked_response_size = config.masked_response_size();
        let npk = config.npk();
        let nm = config.nm();

        let mut offset = 0;

        let evaluated_element = data[offset..offset + noe].to_vec();
        offset += noe;

        let masking_nonce = data[offset..offset + nn].to_vec();
        offset += nn;

        let masked_response = data[offset..offset + masked_response_size].to_vec();
        offset += masked_response_size;

        let credential_response = CredentialResponse {
            evaluated_element,
            masking_nonce,
            masked_response,
        };

        let server_nonce = data[offset..offset + nn].to_vec();
        offset += nn;

        let server_ake_public_key = data[offset..offset + npk].to_vec();
        offset += npk;

        let server_mac = data[offset..offset + nm].to_vec();

        Self {
            credential_response,
            server_nonce,
            server_ake_public_key,
            server_mac,
        }
    }
}

/// Client's final AKE message.
#[derive(Clone, Debug)]
pub struct KE3 {
    pub client_mac: Vec<u8>,
}

/// OPRF blinded element from the client.
#[derive(Clone, Debug)]
pub struct CredentialRequest {
    pub blinded_element: Vec<u8>,
}

/// Server's credential response during authentication.
#[derive(Clone, Debug)]
pub struct CredentialResponse {
    pub evaluated_element: Vec<u8>,
    pub masking_nonce: Vec<u8>,
    pub masked_response: Vec<u8>,
}

/// Client's registration request.
#[derive(Clone, Debug)]
pub struct RegistrationRequest {
    pub blinded_element: Vec<u8>,
}

/// Server's registration response.
#[derive(Clone, Debug)]
pub struct RegistrationResponse {
    pub evaluated_element: Vec<u8>,
    pub server_public_key: Vec<u8>,
}

/// Server-stored registration record.
#[derive(Clone, Debug)]
pub struct RegistrationRecord {
    pub client_public_key: Vec<u8>,
    pub masking_key: Vec<u8>,
    pub envelope: Envelope,
}

/// OPAQUE envelope: protects the client's private key.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub envelope_nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

impl Envelope {
    pub fn serialize(&self) -> Vec<u8> {
        concat(&[&self.envelope_nonce, &self.auth_tag])
    }

    pub fn deserialize(data: &[u8], offset: usize, nonce_len: usize, tag_len: usize) -> Self {
        Self {
            envelope_nonce: data[offset..offset + nonce_len].to_vec(),
            auth_tag: data[offset + nonce_len..offset + nonce_len + tag_len].to_vec(),
        }
    }
}

/// Cleartext credentials for identity binding.
#[derive(Clone, Debug)]
pub struct CleartextCredentials {
    pub server_public_key: Vec<u8>,
    pub server_identity: Vec<u8>,
    pub client_identity: Vec<u8>,
}

impl CleartextCredentials {
    /// Creates cleartext credentials, defaulting identities to public keys when None.
    pub fn create(
        server_public_key: &[u8],
        client_public_key: &[u8],
        server_identity: Option<&[u8]>,
        client_identity: Option<&[u8]>,
    ) -> Self {
        Self {
            server_public_key: server_public_key.to_vec(),
            server_identity: server_identity.unwrap_or(server_public_key).to_vec(),
            client_identity: client_identity.unwrap_or(client_public_key).to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        concat(&[
            &self.server_public_key,
            &i2osp(self.server_identity.len() as u32, 2),
            &self.server_identity,
            &i2osp(self.client_identity.len() as u32, 2),
            &self.client_identity,
        ])
    }
}

/// Client-side state during authentication (after generateKE1).
pub struct ClientAuthState {
    pub blind: Vec<u8>,
    pub password: Vec<u8>,
    pub ke1: KE1,
    pub client_ake_private_key: Vec<u8>,
}

impl Drop for ClientAuthState {
    fn drop(&mut self) {
        self.password.zeroize();
        self.blind.zeroize();
        self.client_ake_private_key.zeroize();
    }
}

/// Client-side state during registration.
pub struct ClientRegistrationState {
    pub blind: Vec<u8>,
    pub password: Vec<u8>,
    pub request: RegistrationRequest,
}

impl Drop for ClientRegistrationState {
    fn drop(&mut self) {
        self.password.zeroize();
        self.blind.zeroize();
    }
}

/// Server-side state after GenerateKE2.
#[derive(Clone)]
pub struct ServerAuthState {
    pub expected_client_mac: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Result of successful client authentication.
pub struct AuthResult {
    pub ke3: KE3,
    pub session_key: Vec<u8>,
    pub export_key: Vec<u8>,
}

/// Bundle wrapping server GenerateKE2 result.
pub struct ServerKE2Result {
    pub server_auth_state: ServerAuthState,
    pub ke2: KE2,
}
