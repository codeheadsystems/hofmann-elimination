use crate::common::{concat, xor};
use crate::opaque::config::OpaqueConfig;
use crate::opaque::config::NN;
use crate::opaque::internal::opaque_envelope::{self, RecoverResult};
use crate::opaque::internal::opaque_oprf;
use crate::opaque::model::*;

/// Client creates a registration request by blinding the password.
pub fn create_registration_request(
    password: &[u8],
    config: &OpaqueConfig,
    rng: &mut dyn rand_core::CryptoRngCore,
) -> ClientRegistrationState {
    let blind = config.cipher_suite().oprf_suite().random_scalar(rng);
    create_registration_request_with_blind(password, &blind, config)
}

/// Client creates a registration request with a given blinding factor (for deterministic testing).
pub fn create_registration_request_with_blind(
    password: &[u8],
    blind: &[u8],
    config: &OpaqueConfig,
) -> ClientRegistrationState {
    let blinded_element = opaque_oprf::blind(config.cipher_suite(), password, blind);
    ClientRegistrationState {
        blind: blind.to_vec(),
        password: password.to_vec(),
        request: RegistrationRequest { blinded_element },
    }
}

/// Server creates a registration response: evaluates OPRF and includes server public key.
pub fn create_registration_response(
    config: &OpaqueConfig,
    request: &RegistrationRequest,
    server_public_key: &[u8],
    credential_identifier: &[u8],
    oprf_seed: &[u8],
) -> Result<RegistrationResponse, &'static str> {
    let oprf_key =
        opaque_oprf::derive_oprf_key(config.cipher_suite(), oprf_seed, credential_identifier);
    let evaluated_element =
        opaque_oprf::blind_evaluate(config.cipher_suite(), &oprf_key, &request.blinded_element)?;
    Ok(RegistrationResponse {
        evaluated_element,
        server_public_key: server_public_key.to_vec(),
    })
}

/// Client finalizes registration: derives randomized_pwd, stores envelope.
pub fn finalize_registration(
    state: &ClientRegistrationState,
    response: &RegistrationResponse,
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
    config: &OpaqueConfig,
    rng: &mut dyn rand_core::CryptoRngCore,
) -> Result<RegistrationRecord, &'static str> {
    let mut nonce = vec![0u8; NN];
    rng.fill_bytes(&mut nonce);
    finalize_registration_with_nonce(
        state,
        response,
        server_identity,
        client_identity,
        config,
        &nonce,
    )
}

/// Client finalizes registration with a provided nonce (for deterministic testing).
pub fn finalize_registration_with_nonce(
    state: &ClientRegistrationState,
    response: &RegistrationResponse,
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
    config: &OpaqueConfig,
    envelope_nonce: &[u8],
) -> Result<RegistrationRecord, &'static str> {
    let randomized_pwd = derive_randomized_pwd(
        &state.password,
        &state.blind,
        &response.evaluated_element,
        config,
    )?;

    let stored = opaque_envelope::store(
        config,
        &randomized_pwd,
        &response.server_public_key,
        server_identity,
        client_identity,
        envelope_nonce,
    );

    Ok(RegistrationRecord {
        client_public_key: stored.client_public_key,
        masking_key: stored.masking_key,
        envelope: stored.envelope,
    })
}

/// Server creates a credential response for authentication.
pub fn create_credential_response_with_nonce(
    config: &OpaqueConfig,
    request: &CredentialRequest,
    server_public_key: &[u8],
    record: &RegistrationRecord,
    credential_identifier: &[u8],
    oprf_seed: &[u8],
    masking_nonce: &[u8],
) -> Result<CredentialResponse, &'static str> {
    let oprf_key =
        opaque_oprf::derive_oprf_key(config.cipher_suite(), oprf_seed, credential_identifier);
    let evaluated_element =
        opaque_oprf::blind_evaluate(config.cipher_suite(), &oprf_key, &request.blinded_element)?;

    // pad = HKDF-Expand(masking_key, masking_nonce || "CredentialResponsePad", Npk + Nn + Nm)
    let pad_info = concat(&[masking_nonce, b"CredentialResponsePad"]);
    let pad = config.cipher_suite().hkdf_expand(
        &record.masking_key,
        &pad_info,
        config.masked_response_size(),
    );

    // plaintext = server_public_key || envelope_nonce || auth_tag
    let plaintext = concat(&[server_public_key, &record.envelope.serialize()]);
    let masked_response = xor(&pad, &plaintext);

    Ok(CredentialResponse {
        evaluated_element,
        masking_nonce: masking_nonce.to_vec(),
        masked_response,
    })
}

/// Client recovers credentials from the credential response during authentication.
pub fn recover_credentials(
    password: &[u8],
    blind: &[u8],
    response: &CredentialResponse,
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
    config: &OpaqueConfig,
) -> Result<RecoverResult, &'static str> {
    let randomized_pwd =
        derive_randomized_pwd(password, blind, &response.evaluated_element, config)?;

    // Recover masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    let masking_key =
        config
            .cipher_suite()
            .hkdf_expand(&randomized_pwd, b"MaskingKey", config.nh());

    // Unmask
    let pad_info = concat(&[&response.masking_nonce, b"CredentialResponsePad"]);
    let pad =
        config
            .cipher_suite()
            .hkdf_expand(&masking_key, &pad_info, config.masked_response_size());
    let plaintext = xor(&pad, &response.masked_response);

    // Extract server_public_key || envelope
    let server_public_key = plaintext[..config.npk()].to_vec();
    let envelope = Envelope::deserialize(&plaintext, config.npk(), NN, config.nm());

    opaque_envelope::recover(
        config,
        &randomized_pwd,
        &server_public_key,
        &envelope,
        server_identity,
        client_identity,
    )
}

/// Derives randomized password from OPRF output.
///
/// Returns `Err` if `evaluated_element` (from the server) is not a valid
/// non-identity group element.
pub fn derive_randomized_pwd(
    password: &[u8],
    blind: &[u8],
    evaluated_element: &[u8],
    config: &OpaqueConfig,
) -> Result<Vec<u8>, &'static str> {
    let oprf_output =
        opaque_oprf::finalize(config.cipher_suite(), password, blind, evaluated_element)?;
    let stretched_output = config.stretch_password(&oprf_output);
    Ok(config
        .cipher_suite()
        .hkdf_extract(&[], &concat(&[&oprf_output, &stretched_output])))
}
