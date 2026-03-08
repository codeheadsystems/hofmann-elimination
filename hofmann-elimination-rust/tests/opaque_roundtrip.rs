use hofmann_rfc::opaque::config::{OpaqueCipherSuite, OpaqueConfig};
use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};

fn run_opaque_roundtrip(config: OpaqueConfig, suite_name: &str) {
    let mut rng = rand::thread_rng();
    let password = b"correct-horse-battery-staple";
    let credential_id = b"user@example.com";

    // --- Registration ---
    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Client: create registration request
    let reg_state = client.create_registration_request(password, &mut rng);

    // Server: create registration response
    let reg_response = server.create_registration_response(&reg_state.request, credential_id);

    // Client: finalize registration
    let record = client.finalize_registration(&reg_state, &reg_response, None, None, &mut rng);

    // --- Authentication ---

    // Client: generate KE1
    let auth_state = client.generate_ke1(password, &mut rng);

    // Server: generate KE2
    let ke2_result = server.generate_ke2(
        None,
        &record,
        credential_id,
        &auth_state.ke1,
        None,
        &mut rng,
    );

    // Client: generate KE3
    let auth_result = client
        .generate_ke3(&auth_state, None, None, &ke2_result.ke2)
        .expect(&format!("Client KE3 failed for {}", suite_name));

    // Server: finish
    let server_session_key = server
        .server_finish(&ke2_result.server_auth_state, &auth_result.ke3)
        .expect(&format!("Server finish failed for {}", suite_name));

    // Session keys must match
    assert_eq!(
        auth_result.session_key, server_session_key,
        "Session keys don't match for {}",
        suite_name
    );

    // Session key should not be empty
    assert!(
        !server_session_key.is_empty(),
        "Session key is empty for {}",
        suite_name
    );

    println!(
        "{}: OPAQUE roundtrip successful, session key length = {} bytes",
        suite_name,
        server_session_key.len()
    );
}

#[test]
fn test_opaque_roundtrip_p256() {
    let config = OpaqueConfig::for_testing();
    run_opaque_roundtrip(config, "P256_SHA256");
}

#[test]
fn test_opaque_roundtrip_p384() {
    let config = OpaqueConfig::for_testing_with_suite(OpaqueCipherSuite::p384_sha384());
    run_opaque_roundtrip(config, "P384_SHA384");
}

#[test]
fn test_opaque_roundtrip_p521() {
    let config = OpaqueConfig::for_testing_with_suite(OpaqueCipherSuite::p521_sha512());
    run_opaque_roundtrip(config, "P521_SHA512");
}

#[test]
fn test_opaque_roundtrip_ristretto255() {
    let config = OpaqueConfig::for_testing_with_suite(OpaqueCipherSuite::ristretto255_sha512());
    run_opaque_roundtrip(config, "RISTRETTO255_SHA512");
}

#[test]
fn test_opaque_wrong_password_fails() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::thread_rng();
    let credential_id = b"user@example.com";

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Register with correct password
    let reg_state = client.create_registration_request(b"correct-password", &mut rng);
    let reg_response = server.create_registration_response(&reg_state.request, credential_id);
    let record = client.finalize_registration(&reg_state, &reg_response, None, None, &mut rng);

    // Authenticate with wrong password
    let auth_state = client.generate_ke1(b"wrong-password", &mut rng);
    let ke2_result = server.generate_ke2(
        None,
        &record,
        credential_id,
        &auth_state.ke1,
        None,
        &mut rng,
    );

    let result = client.generate_ke3(&auth_state, None, None, &ke2_result.ke2);
    assert!(
        result.is_err(),
        "Authentication should fail with wrong password"
    );
}

#[test]
fn test_opaque_fake_ke2() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::thread_rng();

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Try to authenticate without registration (fake KE2)
    let auth_state = client.generate_ke1(b"any-password", &mut rng);
    let fake_ke2_result =
        server.generate_fake_ke2(&auth_state.ke1, b"unknown-user", None, None, &mut rng);

    // Client should fail to verify
    let result = client.generate_ke3(&auth_state, None, None, &fake_ke2_result.ke2);
    assert!(result.is_err(), "Fake KE2 should fail authentication");
}

#[test]
fn test_opaque_with_argon2id() {
    let config = OpaqueConfig::with_argon2id(
        OpaqueCipherSuite::p256_sha256(),
        b"OPAQUE-3DH".to_vec(),
        1024, // 1 MiB (small for testing)
        1,
        1,
    );
    run_opaque_roundtrip(config, "P256_SHA256+Argon2id");
}
