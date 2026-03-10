use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use hofmann_rfc::opaque::config::OpaqueConfig;
use hofmann_rfc::opaque::{OpaqueClient, OpaqueServer};
use hofmann_rfc::recovery::{InMemoryRecoveryTokenStore, RecoveryChallenger, RecoveryTokenStore};

// --- Test RecoveryChallenger implementation ---

struct TestChallenger {
    codes: Mutex<HashMap<Vec<u8>, String>>,
}

impl TestChallenger {
    fn new() -> Self {
        Self {
            codes: Mutex::new(HashMap::new()),
        }
    }
}

impl RecoveryChallenger for TestChallenger {
    fn send_challenge(&self, credential_identifier: &[u8]) -> Result<(), String> {
        let mut codes = self.codes.lock().unwrap();
        codes.insert(credential_identifier.to_vec(), "123456".to_string());
        Ok(())
    }

    fn verify_response(&self, credential_identifier: &[u8], challenge_response: &str) -> bool {
        let mut codes = self.codes.lock().unwrap();
        codes
            .remove(credential_identifier)
            .map(|stored| stored == challenge_response)
            .unwrap_or(false)
    }
}

// --- InMemoryRecoveryTokenStore tests ---

#[test]
fn test_store_and_remove() {
    let store = InMemoryRecoveryTokenStore::new();
    store.store("token-1", "cred-1").unwrap();
    assert_eq!(store.remove("token-1"), Some("cred-1".to_string()));
}

#[test]
fn test_remove_is_consume_once() {
    let store = InMemoryRecoveryTokenStore::new();
    store.store("token-1", "cred-1").unwrap();
    assert!(store.remove("token-1").is_some());
    assert!(store.remove("token-1").is_none());
}

#[test]
fn test_remove_unknown_returns_none() {
    let store = InMemoryRecoveryTokenStore::new();
    assert!(store.remove("nonexistent").is_none());
}

#[test]
fn test_peek_does_not_consume() {
    let store = InMemoryRecoveryTokenStore::new();
    store.store("token-1", "cred-1").unwrap();
    assert_eq!(store.peek("token-1"), Some("cred-1".to_string()));
    assert_eq!(store.peek("token-1"), Some("cred-1".to_string()));
    // Still removable
    assert_eq!(store.remove("token-1"), Some("cred-1".to_string()));
}

#[test]
fn test_peek_unknown_returns_none() {
    let store = InMemoryRecoveryTokenStore::new();
    assert!(store.peek("nonexistent").is_none());
}

#[test]
fn test_expired_token_returns_none() {
    let store = InMemoryRecoveryTokenStore::with_config(Duration::from_millis(1), 100);
    store.store("token-1", "cred-1").unwrap();
    std::thread::sleep(Duration::from_millis(10));
    assert!(store.remove("token-1").is_none());
}

#[test]
fn test_expired_token_peek_returns_none() {
    let store = InMemoryRecoveryTokenStore::with_config(Duration::from_millis(1), 100);
    store.store("token-1", "cred-1").unwrap();
    std::thread::sleep(Duration::from_millis(10));
    assert!(store.peek("token-1").is_none());
}

#[test]
fn test_capacity_limit() {
    let store = InMemoryRecoveryTokenStore::with_config(Duration::from_secs(600), 2);
    store.store("t1", "a").unwrap();
    store.store("t2", "b").unwrap();
    let result = store.store("t3", "c");
    assert!(result.is_err());
}

// --- RecoveryChallenger tests ---

#[test]
fn test_challenger_send_and_verify() {
    let challenger = TestChallenger::new();
    let cred = b"user@example.com";

    challenger.send_challenge(cred).unwrap();
    assert!(challenger.verify_response(cred, "123456"));
}

#[test]
fn test_challenger_wrong_code_fails() {
    let challenger = TestChallenger::new();
    let cred = b"user@example.com";

    challenger.send_challenge(cred).unwrap();
    assert!(!challenger.verify_response(cred, "wrong"));
}

#[test]
fn test_challenger_verify_is_consume_once() {
    let challenger = TestChallenger::new();
    let cred = b"user@example.com";

    challenger.send_challenge(cred).unwrap();
    assert!(challenger.verify_response(cred, "123456"));
    // Second verify should fail (code consumed)
    assert!(!challenger.verify_response(cred, "123456"));
}

#[test]
fn test_challenger_unknown_cred_fails() {
    let challenger = TestChallenger::new();
    assert!(!challenger.verify_response(b"unknown", "123456"));
}

// --- Full recovery re-registration flow ---

#[test]
fn test_full_recovery_flow() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::thread_rng();
    let credential_id = b"user@example.com";
    let old_password = b"old-password";
    let new_password = b"new-password";

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);
    let challenger = TestChallenger::new();
    let token_store = InMemoryRecoveryTokenStore::new();

    // --- Step 1: Initial registration with old password ---
    let reg_state = client.create_registration_request(old_password, &mut rng);
    let reg_response = server.create_registration_response(&reg_state.request, credential_id);
    let _old_record =
        client.finalize_registration(&reg_state, &reg_response, None, None, &mut rng);

    // --- Step 2: Recovery flow ---
    // 2a: Send challenge
    challenger.send_challenge(credential_id).unwrap();

    // 2b: Verify challenge → get recovery token
    assert!(challenger.verify_response(credential_id, "123456"));
    let recovery_token = "recovery-token-uuid";
    token_store.store(recovery_token, "dXNlckBleGFtcGxlLmNvbQ==").unwrap();

    // 2c: Validate token during registration start (peek, don't consume)
    let peeked = token_store.peek(recovery_token);
    assert_eq!(peeked, Some("dXNlckBleGFtcGxlLmNvbQ==".to_string()));

    // --- Step 3: Re-register with new password ---
    let new_reg_state = client.create_registration_request(new_password, &mut rng);
    let new_reg_response =
        server.create_registration_response(&new_reg_state.request, credential_id);
    let new_record =
        client.finalize_registration(&new_reg_state, &new_reg_response, None, None, &mut rng);

    // Consume the recovery token
    let consumed = token_store.remove(recovery_token);
    assert_eq!(consumed, Some("dXNlckBleGFtcGxlLmNvbQ==".to_string()));

    // Token should be gone now
    assert!(token_store.remove(recovery_token).is_none());

    // --- Step 4: Authenticate with new password ---
    let auth_state = client.generate_ke1(new_password, &mut rng);
    let ke2_result = server.generate_ke2(
        None,
        &new_record,
        credential_id,
        &auth_state.ke1,
        None,
        &mut rng,
    );
    let auth_result = client
        .generate_ke3(&auth_state, None, None, &ke2_result.ke2)
        .expect("Auth with new password should succeed");
    let session_key = server
        .server_finish(&ke2_result.server_auth_state, &auth_result.ke3)
        .expect("Server finish should succeed");
    assert_eq!(auth_result.session_key, session_key);

    println!("Full recovery flow succeeded: re-registered and authenticated with new password");
}

#[test]
fn test_old_password_fails_after_recovery() {
    let config = OpaqueConfig::for_testing();
    let mut rng = rand::thread_rng();
    let credential_id = b"user@example.com";
    let old_password = b"old-password";
    let new_password = b"new-password";

    let server = OpaqueServer::generate(&config, &mut rng);
    let client = OpaqueClient::new(&config);

    // Register with old password
    let reg_state = client.create_registration_request(old_password, &mut rng);
    let reg_response = server.create_registration_response(&reg_state.request, credential_id);
    let _old_record =
        client.finalize_registration(&reg_state, &reg_response, None, None, &mut rng);

    // Re-register with new password (simulating recovery)
    let new_reg_state = client.create_registration_request(new_password, &mut rng);
    let new_reg_response =
        server.create_registration_response(&new_reg_state.request, credential_id);
    let new_record =
        client.finalize_registration(&new_reg_state, &new_reg_response, None, None, &mut rng);

    // Try to authenticate with old password — should fail
    let auth_state = client.generate_ke1(old_password, &mut rng);
    let ke2_result = server.generate_ke2(
        None,
        &new_record,
        credential_id,
        &auth_state.ke1,
        None,
        &mut rng,
    );
    let result = client.generate_ke3(&auth_state, None, None, &ke2_result.ke2);
    assert!(
        result.is_err(),
        "Old password should fail after re-registration"
    );
}
