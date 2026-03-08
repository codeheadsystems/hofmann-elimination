//! CFRG OPAQUE reference test vectors (P256-SHA256, Identity KSF).
//!
//! Ported from the Java OpaqueVectorsTest.java. Tests both without explicit
//! identities (Vector 1) and with explicit identities (Vector 2).

use hofmann_rfc::opaque::config::OpaqueConfig;
use hofmann_rfc::opaque::model::*;
use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn serialize_ke2(ke2: &KE2) -> Vec<u8> {
    [
        ke2.credential_response.evaluated_element.as_slice(),
        ke2.credential_response.masking_nonce.as_slice(),
        ke2.credential_response.masked_response.as_slice(),
        ke2.server_nonce.as_slice(),
        ke2.server_ake_public_key.as_slice(),
        ke2.server_mac.as_slice(),
    ]
    .concat()
}

// --- Shared inputs ---

fn password() -> Vec<u8> {
    hex("436f7272656374486f72736542617474657279537461706c65")
}

fn credential_identifier() -> Vec<u8> {
    hex("31323334")
}

fn oprf_seed() -> Vec<u8> {
    hex("62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2")
}

fn server_private_key() -> Vec<u8> {
    hex("c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5")
}

fn server_public_key() -> Vec<u8> {
    hex("035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874")
}

fn blind_registration() -> Vec<u8> {
    hex("411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153")
}

fn envelope_nonce() -> Vec<u8> {
    hex("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f")
}

fn blind_login() -> Vec<u8> {
    hex("c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1")
}

fn client_nonce() -> Vec<u8> {
    hex("ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1")
}

fn client_keyshare_seed() -> Vec<u8> {
    hex("633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc")
}

fn masking_nonce() -> Vec<u8> {
    hex("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d")
}

fn server_nonce() -> Vec<u8> {
    hex("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1")
}

fn server_keyshare_seed() -> Vec<u8> {
    hex("05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f")
}

// --- Vector 1 expected outputs (no explicit identities) ---

fn expected_registration_request() -> Vec<u8> {
    hex("029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8")
}

fn expected_registration_response() -> Vec<u8> {
    hex("0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874")
}

fn expected_registration_upload() -> Vec<u8> {
    hex("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8")
}

fn expected_ke1() -> Vec<u8> {
    hex("037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6")
}

fn expected_ke2() -> Vec<u8> {
    hex("0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b")
}

fn expected_ke3() -> Vec<u8> {
    hex("e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e")
}

fn expected_session_key() -> Vec<u8> {
    hex("484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1")
}

fn expected_export_key() -> Vec<u8> {
    hex("c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b")
}

// --- Vector 2 expected outputs (with explicit identities) ---

fn client_identity_v2() -> Vec<u8> {
    hex("616c696365")
}

fn server_identity_v2() -> Vec<u8> {
    hex("626f62")
}

fn expected_registration_upload_v2() -> Vec<u8> {
    hex("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971")
}

fn expected_ke3_v2() -> Vec<u8> {
    hex("46833578cee137775f6be3f01b80748daac5a694101ad0e9e7025480552da56a")
}

fn expected_session_key_v2() -> Vec<u8> {
    hex("27766fabd8dd88ff37fbd0ef1a491e601d10d9f016c2b28c4bd1b0fb7511a3c3")
}

fn expected_export_key_v2() -> Vec<u8> {
    hex("c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b")
}

// --- Helper: build config, client, server ---

fn make_config() -> OpaqueConfig {
    OpaqueConfig::for_testing()
}

fn make_server(config: &OpaqueConfig) -> OpaqueServer<'_> {
    OpaqueServer::new(
        server_private_key(),
        server_public_key(),
        oprf_seed(),
        config,
    )
}

// --- Helper: registration flow ---

fn do_registration(
    client: &OpaqueClient,
    server: &OpaqueServer,
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
) -> (ClientRegistrationState, RegistrationResponse, RegistrationRecord) {
    let state = client.create_registration_request_deterministic(&password(), &blind_registration());
    let response = server.create_registration_response(&state.request, &credential_identifier());
    let record = client.finalize_registration_deterministic(
        &state,
        &response,
        server_identity,
        client_identity,
        &envelope_nonce(),
    );
    (state, response, record)
}

// --- Helper: full auth flow ---

fn do_full_auth(
    client: &OpaqueClient,
    server: &OpaqueServer,
    record: &RegistrationRecord,
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
) -> (ClientAuthState, ServerKE2Result, AuthResult) {
    let auth_state = client.generate_ke1_deterministic(
        &password(),
        &blind_login(),
        &client_nonce(),
        &client_keyshare_seed(),
    );

    let ke2_result = server.generate_ke2_deterministic(
        server_identity,
        record,
        &credential_identifier(),
        &auth_state.ke1,
        client_identity,
        &masking_nonce(),
        &server_keyshare_seed(),
        &server_nonce(),
    );

    let auth_result = client
        .generate_ke3(&auth_state, client_identity, server_identity, &ke2_result.ke2)
        .expect("Client KE3 should succeed");

    (auth_state, ke2_result, auth_result)
}

// =====================================================================
// Vector 1: no explicit identities
// =====================================================================

#[test]
fn vector1_registration_request() {
    let config = make_config();
    let client = OpaqueClient::new(&config);

    let state = client.create_registration_request_deterministic(&password(), &blind_registration());

    assert_eq!(
        state.request.blinded_element,
        expected_registration_request(),
        "Registration request blinded_element mismatch"
    );
}

#[test]
fn vector1_registration_response() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let state = client.create_registration_request_deterministic(&password(), &blind_registration());
    let response = server.create_registration_response(&state.request, &credential_identifier());

    let actual = [
        response.evaluated_element.as_slice(),
        response.server_public_key.as_slice(),
    ]
    .concat();

    assert_eq!(
        actual,
        expected_registration_response(),
        "Registration response mismatch"
    );
}

#[test]
fn vector1_registration_upload() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let (_, _, record) = do_registration(&client, &server, None, None);

    let actual = [
        record.client_public_key.as_slice(),
        record.masking_key.as_slice(),
        record.envelope.serialize().as_slice(),
    ]
    .concat();

    assert_eq!(
        actual,
        expected_registration_upload(),
        "Registration upload mismatch"
    );
}

#[test]
fn vector1_ke1() {
    let config = make_config();
    let client = OpaqueClient::new(&config);

    let auth_state = client.generate_ke1_deterministic(
        &password(),
        &blind_login(),
        &client_nonce(),
        &client_keyshare_seed(),
    );

    assert_eq!(
        auth_state.ke1.serialize(),
        expected_ke1(),
        "KE1 serialization mismatch"
    );
}

#[test]
fn vector1_ke2() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let (_, _, record) = do_registration(&client, &server, None, None);

    let auth_state = client.generate_ke1_deterministic(
        &password(),
        &blind_login(),
        &client_nonce(),
        &client_keyshare_seed(),
    );

    let ke2_result = server.generate_ke2_deterministic(
        None,
        &record,
        &credential_identifier(),
        &auth_state.ke1,
        None,
        &masking_nonce(),
        &server_keyshare_seed(),
        &server_nonce(),
    );

    assert_eq!(
        serialize_ke2(&ke2_result.ke2),
        expected_ke2(),
        "KE2 serialization mismatch"
    );
}

#[test]
fn vector1_ke3_and_session_key() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let (_, _, record) = do_registration(&client, &server, None, None);
    let (_, _, auth_result) = do_full_auth(&client, &server, &record, None, None);

    assert_eq!(
        auth_result.ke3.client_mac,
        expected_ke3(),
        "KE3 client_mac mismatch"
    );
    assert_eq!(
        auth_result.session_key,
        expected_session_key(),
        "Session key mismatch"
    );
    assert_eq!(
        auth_result.export_key,
        expected_export_key(),
        "Export key mismatch"
    );
}

#[test]
fn vector1_server_finish() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let (_, _, record) = do_registration(&client, &server, None, None);
    let (_, ke2_result, auth_result) = do_full_auth(&client, &server, &record, None, None);

    let server_session_key = server
        .server_finish(&ke2_result.server_auth_state, &auth_result.ke3)
        .expect("Server finish should succeed");

    assert_eq!(
        server_session_key,
        expected_session_key(),
        "Server session key mismatch"
    );
}

// =====================================================================
// Vector 2: with explicit identities (client="alice", server="bob")
// =====================================================================

#[test]
fn vector2_registration_upload() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let sid = server_identity_v2();
    let cid = client_identity_v2();
    let (_, _, record) = do_registration(&client, &server, Some(&sid), Some(&cid));

    let actual = [
        record.client_public_key.as_slice(),
        record.masking_key.as_slice(),
        record.envelope.serialize().as_slice(),
    ]
    .concat();

    assert_eq!(
        actual,
        expected_registration_upload_v2(),
        "Registration upload V2 mismatch"
    );
}

#[test]
fn vector2_ke3_and_session_key() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let sid = server_identity_v2();
    let cid = client_identity_v2();
    let (_, _, record) = do_registration(&client, &server, Some(&sid), Some(&cid));
    let (_, _, auth_result) =
        do_full_auth(&client, &server, &record, Some(&sid), Some(&cid));

    assert_eq!(
        auth_result.ke3.client_mac,
        expected_ke3_v2(),
        "KE3 V2 client_mac mismatch"
    );
    assert_eq!(
        auth_result.session_key,
        expected_session_key_v2(),
        "Session key V2 mismatch"
    );
    assert_eq!(
        auth_result.export_key,
        expected_export_key_v2(),
        "Export key V2 mismatch"
    );
}

#[test]
fn vector2_server_finish() {
    let config = make_config();
    let client = OpaqueClient::new(&config);
    let server = make_server(&config);

    let sid = server_identity_v2();
    let cid = client_identity_v2();
    let (_, _, record) = do_registration(&client, &server, Some(&sid), Some(&cid));
    let (_, ke2_result, auth_result) =
        do_full_auth(&client, &server, &record, Some(&sid), Some(&cid));

    let server_session_key = server
        .server_finish(&ke2_result.server_auth_state, &auth_result.ke3)
        .expect("Server finish V2 should succeed");

    assert_eq!(
        server_session_key,
        expected_session_key_v2(),
        "Server session key V2 mismatch"
    );
}
