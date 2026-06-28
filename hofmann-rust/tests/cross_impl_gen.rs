//! Generator for cross-implementation OPAQUE conformance vectors.
//!
//! Not a permanent test — run with `cargo test --test cross_impl_gen -- --nocapture`
//! to emit deterministic wire vectors for P384/P521/Ristretto255, which are then
//! asserted byte-for-byte by the Java OpaqueCrossImplVectorsTest. Independent
//! implementations agreeing on these bytes is real conformance evidence (the
//! suites have no published CFRG OPAQUE known-answer vectors).

use hofmann_rfc::opaque::config::{OpaqueConfig, OpaqueCipherSuite};
use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// Fixed, distinct byte patterns. Nonces and keyshare seeds are 32 bytes (Nn / Nseed).
fn nonce(tag: u8) -> Vec<u8> {
    (0..32).map(|i| tag ^ (i as u8)).collect()
}

fn run(name: &str, suite: OpaqueCipherSuite) {
    let config = OpaqueConfig::for_testing_with_suite(suite);

    let password = b"CorrectHorseBatteryStaple".to_vec();
    let credential_identifier = b"1234".to_vec();

    // Derive a deterministic server key pair for this suite from a fixed seed.
    let server_key_seed: Vec<u8> = (0..32).map(|i| 0x10 ^ i as u8).collect();
    let keypair = config.cipher_suite().derive_ake_key_pair(&server_key_seed);
    let server_private_key = keypair.private_key.clone();
    let server_public_key = keypair.public_key.clone();
    let scalar_width = server_private_key.len();

    // oprf_seed is Nh bytes (hash output length).
    let oprf_seed: Vec<u8> = (0..config.nh()).map(|i| 0x20 ^ i as u8).collect();

    // Small valid scalars (< curve order) of the correct width for blinds.
    let mut blind_registration = vec![0u8; scalar_width];
    blind_registration[scalar_width - 1] = 0x42;
    let mut blind_login = vec![0u8; scalar_width];
    blind_login[scalar_width - 1] = 0x37;

    let envelope_nonce = nonce(0xA1);
    let client_nonce = nonce(0xB2);
    let client_keyshare_seed = nonce(0xC3);
    let masking_nonce = nonce(0xD4);
    let server_nonce = nonce(0xE5);
    let server_keyshare_seed = nonce(0xF6);

    let client = OpaqueClient::new(&config);
    let server = OpaqueServer::new(
        server_private_key.clone(),
        server_public_key.clone(),
        oprf_seed.clone(),
        &config,
    );

    // Registration.
    let reg_state = client.create_registration_request_deterministic(&password, &blind_registration);
    let reg_response = server
        .create_registration_response(&reg_state.request, &credential_identifier)
        .unwrap();
    let record = client
        .finalize_registration_deterministic(&reg_state, &reg_response, None, None, &envelope_nonce)
        .unwrap();

    let registration_request = reg_state.request.blinded_element.clone();
    let mut registration_response = reg_response.evaluated_element.clone();
    registration_response.extend_from_slice(&reg_response.server_public_key);
    let mut registration_upload = record.client_public_key.clone();
    registration_upload.extend_from_slice(&record.masking_key);
    registration_upload.extend_from_slice(&record.envelope.serialize());

    // Authentication.
    let auth_state = client.generate_ke1_deterministic(
        &password,
        &blind_login,
        &client_nonce,
        &client_keyshare_seed,
    );
    let ke1 = auth_state.ke1.serialize();

    let ke2_result = server
        .generate_ke2_deterministic(
            None,
            &record,
            &credential_identifier,
            &auth_state.ke1,
            None,
            &masking_nonce,
            &server_keyshare_seed,
            &server_nonce,
        )
        .unwrap();
    let ke2 = &ke2_result.ke2;
    let mut ke2_bytes = ke2.credential_response.evaluated_element.clone();
    ke2_bytes.extend_from_slice(&ke2.credential_response.masking_nonce);
    ke2_bytes.extend_from_slice(&ke2.credential_response.masked_response);
    ke2_bytes.extend_from_slice(&ke2.server_nonce);
    ke2_bytes.extend_from_slice(&ke2.server_ake_public_key);
    ke2_bytes.extend_from_slice(&ke2.server_mac);

    let auth_result = client
        .generate_ke3(&auth_state, None, None, &ke2_result.ke2)
        .expect("client KE3 should succeed");

    // Sanity: server confirms client MAC and both sides agree on the session key.
    let server_session_key = server
        .server_finish(&ke2_result.server_auth_state, &auth_result.ke3)
        .expect("server finish should succeed");
    assert_eq!(server_session_key, auth_result.session_key);

    let p = |k: &str, v: &[u8]| println!("{}|{}|{}", name, k, hexs(v));
    p("password", &password);
    p("credential_identifier", &credential_identifier);
    p("server_private_key", &server_private_key);
    p("server_public_key", &server_public_key);
    p("oprf_seed", &oprf_seed);
    p("blind_registration", &blind_registration);
    p("blind_login", &blind_login);
    p("envelope_nonce", &envelope_nonce);
    p("client_nonce", &client_nonce);
    p("client_keyshare_seed", &client_keyshare_seed);
    p("masking_nonce", &masking_nonce);
    p("server_nonce", &server_nonce);
    p("server_keyshare_seed", &server_keyshare_seed);
    p("registration_request", &registration_request);
    p("registration_response", &registration_response);
    p("registration_upload", &registration_upload);
    p("ke1", &ke1);
    p("ke2", &ke2_bytes);
    p("ke3", &auth_result.ke3.client_mac);
    p("session_key", &auth_result.session_key);
    p("export_key", &auth_result.export_key);
}

#[test]
fn generate_cross_impl_vectors() {
    run("P384_SHA384", OpaqueCipherSuite::p384_sha384());
    run("P521_SHA512", OpaqueCipherSuite::p521_sha512());
    run("RISTRETTO255_SHA512", OpaqueCipherSuite::ristretto255_sha512());
}
