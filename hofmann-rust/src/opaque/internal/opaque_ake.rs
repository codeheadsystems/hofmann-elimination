use crate::common::{concat, ct_eq, i2osp};
use crate::opaque::config::OpaqueConfig;
use crate::opaque::config::NN;
use crate::opaque::internal::opaque_credentials;
use crate::opaque::model::*;
use zeroize::Zeroize;

/// Keys derived from the 3DH input key material and preamble.
struct DerivedKeys {
    km2: Vec<u8>,
    km3: Vec<u8>,
    session_key: Vec<u8>,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.km2.zeroize();
        self.km3.zeroize();
        self.session_key.zeroize();
    }
}

fn encode_vector(data: &[u8]) -> Vec<u8> {
    concat(&[&i2osp(data.len() as u32, 2), data])
}

fn serialize_credential_response(cr: &CredentialResponse) -> Vec<u8> {
    concat(&[
        &cr.evaluated_element,
        &cr.masking_nonce,
        &cr.masked_response,
    ])
}

/// Constructs the preamble for key derivation.
pub fn build_preamble(
    context: &[u8],
    client_identity: &[u8],
    ke1: &KE1,
    server_identity: &[u8],
    credential_response: &CredentialResponse,
    server_nonce: &[u8],
    server_ake_public_key: &[u8],
) -> Vec<u8> {
    concat(&[
        b"OPAQUEv1-",
        &encode_vector(context),
        &encode_vector(client_identity),
        &ke1.serialize(),
        &encode_vector(server_identity),
        &serialize_credential_response(credential_response),
        server_nonce,
        server_ake_public_key,
    ])
}

/// Derives session keys from the triple-DH input key material and preamble.
///
/// Produces `km2` (server MAC key), `km3` (client MAC key), and the
/// shared `session_key` via HKDF-Extract + HKDF-Expand-Label.
fn derive_keys(config: &OpaqueConfig, ikm: &[u8], preamble: &[u8]) -> DerivedKeys {
    let suite = config.cipher_suite();
    let prk = suite.hkdf_extract(&[], ikm);
    let preamble_hash = suite.hash(preamble);

    let handshake_secret =
        suite.hkdf_expand_label(&prk, b"HandshakeSecret", &preamble_hash, config.nx());
    let session_key = suite.hkdf_expand_label(&prk, b"SessionKey", &preamble_hash, config.nx());

    let km2 = suite.hkdf_expand_label(&handshake_secret, b"ServerMAC", &[], config.nm());
    let km3 = suite.hkdf_expand_label(&handshake_secret, b"ClientMAC", &[], config.nm());

    DerivedKeys {
        km2,
        km3,
        session_key,
    }
}

/// Server GenerateKE2 with deterministic nonces and seeds.
#[allow(clippy::too_many_arguments)]
pub fn generate_ke2_deterministic(
    config: &OpaqueConfig,
    server_identity: Option<&[u8]>,
    server_private_key: &[u8],
    server_public_key: &[u8],
    record: &RegistrationRecord,
    credential_identifier: &[u8],
    oprf_seed: &[u8],
    ke1: &KE1,
    client_identity: Option<&[u8]>,
    masking_nonce: &[u8],
    server_ake_key_seed: &[u8],
    server_nonce: &[u8],
) -> Result<ServerKE2Result, &'static str> {
    let suite = config.cipher_suite();

    let s_id = server_identity.unwrap_or(server_public_key);
    let c_id = client_identity.unwrap_or(&record.client_public_key);

    let cred_req = CredentialRequest {
        blinded_element: ke1.credential_request.blinded_element.clone(),
    };
    let cred_response = opaque_credentials::create_credential_response_with_nonce(
        config,
        &cred_req,
        server_public_key,
        record,
        credential_identifier,
        oprf_seed,
        masking_nonce,
    )?;

    let server_ake_kp = suite.derive_ake_key_pair(server_ake_key_seed);
    let server_ake_sk = server_ake_kp.private_key;
    let server_ake_pk = server_ake_kp.public_key;

    let preamble = build_preamble(
        config.context(),
        c_id,
        ke1,
        s_id,
        &cred_response,
        server_nonce,
        &server_ake_pk,
    );

    // dh1/dh2 multiply the client-supplied AKE public key, so a malformed or
    // identity key returns Err instead of panicking the server thread.
    let gs = suite.oprf_suite().group_spec();
    let dh1 = gs.scalar_multiply(&server_ake_sk, &ke1.client_ake_public_key)?;
    let dh2 = gs.scalar_multiply(server_private_key, &ke1.client_ake_public_key)?;
    let dh3 = gs.scalar_multiply(&server_ake_sk, &record.client_public_key)?;
    let ikm = concat(&[&dh1, &dh2, &dh3]);

    let mut keys = derive_keys(config, &ikm, &preamble);
    let preamble_hash = suite.hash(&preamble);
    let server_mac = suite.hmac(&keys.km2, &preamble_hash);
    let expected_client_mac =
        suite.hmac(&keys.km3, &suite.hash(&concat(&[&preamble, &server_mac])));

    let auth_state = ServerAuthState {
        expected_client_mac,
        session_key: std::mem::take(&mut keys.session_key),
    };
    let ke2 = KE2 {
        credential_response: cred_response,
        server_nonce: server_nonce.to_vec(),
        server_ake_public_key: server_ake_pk,
        server_mac,
    };

    Ok(ServerKE2Result {
        server_auth_state: auth_state,
        ke2,
    })
}

/// Server GenerateKE2 with random nonces.
#[allow(clippy::too_many_arguments)]
pub fn generate_ke2(
    config: &OpaqueConfig,
    server_identity: Option<&[u8]>,
    server_private_key: &[u8],
    server_public_key: &[u8],
    record: &RegistrationRecord,
    credential_identifier: &[u8],
    oprf_seed: &[u8],
    ke1: &KE1,
    client_identity: Option<&[u8]>,
    rng: &mut dyn rand_core::CryptoRng,
) -> Result<ServerKE2Result, &'static str> {
    let mut masking_nonce = vec![0u8; NN];
    rng.fill_bytes(&mut masking_nonce);
    let mut server_ake_key_seed = vec![0u8; NN];
    rng.fill_bytes(&mut server_ake_key_seed);
    let mut server_nonce = vec![0u8; NN];
    rng.fill_bytes(&mut server_nonce);

    generate_ke2_deterministic(
        config,
        server_identity,
        server_private_key,
        server_public_key,
        record,
        credential_identifier,
        oprf_seed,
        ke1,
        client_identity,
        &masking_nonce,
        &server_ake_key_seed,
        &server_nonce,
    )
}

/// Client GenerateKE3: recovers credentials, verifies server MAC, computes client MAC.
///
/// Returns the client's KE3 message, session key, and export key on success.
/// Returns `Err` if server MAC verification fails (wrong password or tampered KE2).
pub fn generate_ke3(
    state: &ClientAuthState,
    client_identity: Option<&[u8]>,
    server_identity: Option<&[u8]>,
    ke2: &KE2,
    context: &[u8],
    config: &OpaqueConfig,
) -> Result<AuthResult, &'static str> {
    let suite = config.cipher_suite();

    let recovered = opaque_credentials::recover_credentials(
        &state.password,
        &state.blind,
        &ke2.credential_response,
        server_identity,
        client_identity,
        config,
    )?;

    let c_id = client_identity.unwrap_or(&recovered.client_public_key);
    let s_id = server_identity.unwrap_or(&recovered.cleartext_credentials.server_public_key);

    let preamble = build_preamble(
        context,
        c_id,
        &state.ke1,
        s_id,
        &ke2.credential_response,
        &ke2.server_nonce,
        &ke2.server_ake_public_key,
    );

    // These multiply server-supplied public keys (the ephemeral key from KE2 and
    // the static key recovered from the masked credential response), so a
    // malformed or identity element returns Err instead of panicking the client.
    let gs = suite.oprf_suite().group_spec();
    let dh1 = gs.scalar_multiply(&state.client_ake_private_key, &ke2.server_ake_public_key)?;
    let dh2 = gs.scalar_multiply(
        &state.client_ake_private_key,
        &recovered.cleartext_credentials.server_public_key,
    )?;
    let dh3 = gs.scalar_multiply(&recovered.client_private_key, &ke2.server_ake_public_key)?;
    let ikm = concat(&[&dh1, &dh2, &dh3]);

    let mut keys = derive_keys(config, &ikm, &preamble);
    let preamble_hash = suite.hash(&preamble);
    let expected_server_mac = suite.hmac(&keys.km2, &preamble_hash);

    if !ct_eq(&expected_server_mac, &ke2.server_mac) {
        return Err("Authentication failed");
    }

    let client_mac = suite.hmac(
        &keys.km3,
        &suite.hash(&concat(&[&preamble, &ke2.server_mac])),
    );

    Ok(AuthResult {
        ke3: KE3 { client_mac },
        session_key: std::mem::take(&mut keys.session_key),
        export_key: recovered.export_key,
    })
}
