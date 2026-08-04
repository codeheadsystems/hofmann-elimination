use hofmann_rfc::opaque::config::{OpaqueCipherSuite, OpaqueConfig};
use hofmann_rfc::opaque::model::RegistrationRequest;
use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};

fn run_opaque_roundtrip(config: OpaqueConfig, suite_name: &str) {
    let mut rng = rand::rng();
    let password = b"correct-horse-battery-staple";
    let credential_id = b"user@example.com";

    // --- Registration ---
    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Client: create registration request
    let reg_state = client.create_registration_request(password, &mut rng);

    // Server: create registration response
    let reg_response = server
        .create_registration_response(&reg_state.request, credential_id)
        .unwrap();

    // Client: finalize registration
    let record = client
        .finalize_registration(&reg_state, &reg_response, None, None, &mut rng)
        .unwrap();

    // --- Authentication ---

    // Client: generate KE1
    let auth_state = client.generate_ke1(password, &mut rng);

    // Server: generate KE2
    let ke2_result = server
        .generate_ke2(
            None,
            &record,
            credential_id,
            &auth_state.ke1,
            None,
            &mut rng,
        )
        .unwrap();

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

/// A malicious client can put arbitrary bytes in the blinded element / AKE
/// public key. The server must reject these with an error instead of panicking
/// the handling thread (a remote DoS). Regression test for the panic-on-bad-input
/// fix.
#[test]
fn test_opaque_server_rejects_malformed_request() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::rng();
    let credential_id = b"user@example.com";

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Registration with a garbage blinded element must error, not panic.
    let bad_reg = RegistrationRequest {
        blinded_element: vec![0xff; 5],
    };
    assert!(
        server
            .create_registration_response(&bad_reg, credential_id)
            .is_err(),
        "server must reject a malformed registration blinded element"
    );

    // Establish a real record so we can drive generate_ke2.
    let reg_state = client.create_registration_request(b"pw", &mut rng);
    let reg_response = server
        .create_registration_response(&reg_state.request, credential_id)
        .unwrap();
    let record = client
        .finalize_registration(&reg_state, &reg_response, None, None, &mut rng)
        .unwrap();

    // A KE1 carrying an identity client AKE public key must error, not panic.
    let mut auth_state = client.generate_ke1(b"pw", &mut rng);
    let element_size = config.cipher_suite().npk();
    let mut bad_ke1 = auth_state.ke1.clone();
    bad_ke1.client_ake_public_key = vec![0u8; element_size]; // identity / all-zero
    assert!(
        server
            .generate_ke2(None, &record, credential_id, &bad_ke1, None, &mut rng)
            .is_err(),
        "server must reject an identity client AKE public key"
    );

    // And a KE1 with a malformed blinded element must error too.
    auth_state.ke1.credential_request.blinded_element = vec![0x01, 0x02, 0x03];
    assert!(
        server
            .generate_ke2(
                None,
                &record,
                credential_id,
                &auth_state.ke1,
                None,
                &mut rng
            )
            .is_err(),
        "server must reject a malformed credential request blinded element"
    );
}

/// A malicious server can return a credential response with a truncated masked
/// response. The client must reject it with an error rather than panicking while
/// unmasking/slicing. Regression test for the client-side bounds-check fix.
#[test]
fn test_opaque_client_rejects_truncated_credential_response() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::rng();
    let credential_id = b"user@example.com";

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    let reg_state = client.create_registration_request(b"pw", &mut rng);
    let reg_response = server
        .create_registration_response(&reg_state.request, credential_id)
        .unwrap();
    let record = client
        .finalize_registration(&reg_state, &reg_response, None, None, &mut rng)
        .unwrap();

    let auth_state = client.generate_ke1(b"pw", &mut rng);
    let mut ke2_result = server
        .generate_ke2(
            None,
            &record,
            credential_id,
            &auth_state.ke1,
            None,
            &mut rng,
        )
        .unwrap();

    // Truncate the server-supplied masked response.
    ke2_result
        .ke2
        .credential_response
        .masked_response
        .truncate(3);

    let result = client.generate_ke3(&auth_state, None, None, &ke2_result.ke2);
    assert!(
        result.is_err(),
        "client must reject a truncated credential response without panicking"
    );
}

#[test]
fn test_opaque_wrong_password_fails() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::rng();
    let credential_id = b"user@example.com";

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Register with correct password
    let reg_state = client.create_registration_request(b"correct-password", &mut rng);
    let reg_response = server
        .create_registration_response(&reg_state.request, credential_id)
        .unwrap();
    let record = client
        .finalize_registration(&reg_state, &reg_response, None, None, &mut rng)
        .unwrap();

    // Authenticate with wrong password
    let auth_state = client.generate_ke1(b"wrong-password", &mut rng);
    let ke2_result = server
        .generate_ke2(
            None,
            &record,
            credential_id,
            &auth_state.ke1,
            None,
            &mut rng,
        )
        .unwrap();

    let result = client.generate_ke3(&auth_state, None, None, &ke2_result.ke2);
    assert!(
        result.is_err(),
        "Authentication should fail with wrong password"
    );
}

#[test]
fn test_opaque_fake_ke2() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::rng();

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Try to authenticate without registration (fake KE2)
    let auth_state = client.generate_ke1(b"any-password", &mut rng);
    let fake_ke2_result = server
        .generate_fake_ke2(&auth_state.ke1, b"unknown-user", None, None, &mut rng)
        .unwrap();

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
