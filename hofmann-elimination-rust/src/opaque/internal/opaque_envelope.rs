use crate::common::{concat, ct_eq};
use crate::opaque::config::OpaqueConfig;
use crate::opaque::config::NN;
use crate::opaque::model::{CleartextCredentials, Envelope};

/// Result of the Store operation (RFC 9807 §3.3.1.1).
///
/// Contains the sealed envelope, derived client public key, masking key
/// (for credential response encryption), and export key.
pub struct StoreResult {
    pub envelope: Envelope,
    pub client_public_key: Vec<u8>,
    pub masking_key: Vec<u8>,
    pub export_key: Vec<u8>,
}

/// Result of the Recover operation (RFC 9807 §3.3.1.2).
///
/// Contains the recovered client key pair, cleartext credentials (for
/// identity binding), and export key.
pub struct RecoverResult {
    pub client_private_key: Vec<u8>,
    pub client_public_key: Vec<u8>,
    pub cleartext_credentials: CleartextCredentials,
    pub export_key: Vec<u8>,
}

/// Stores credentials into an envelope per RFC 9807 §3.3.1.1.
pub fn store(
    config: &OpaqueConfig,
    randomized_pwd: &[u8],
    server_public_key: &[u8],
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
    envelope_nonce: &[u8],
) -> StoreResult {
    let suite = config.cipher_suite();

    let masking_key = suite.hkdf_expand(randomized_pwd, b"MaskingKey", config.nh());
    let auth_key = suite.hkdf_expand(
        randomized_pwd,
        &concat(&[envelope_nonce, b"AuthKey"]),
        config.nh(),
    );
    let export_key = suite.hkdf_expand(
        randomized_pwd,
        &concat(&[envelope_nonce, b"ExportKey"]),
        config.nh(),
    );
    // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
    let seed = suite.hkdf_expand(
        randomized_pwd,
        &concat(&[envelope_nonce, b"PrivateKey"]),
        NN,
    );

    let key_pair = suite.derive_ake_key_pair(&seed);
    let client_public_key = key_pair.public_key;

    let cleartext = CleartextCredentials::create(
        server_public_key,
        &client_public_key,
        server_identity,
        client_identity,
    );

    let auth_input = concat(&[envelope_nonce, &cleartext.serialize()]);
    let auth_tag = suite.hmac(&auth_key, &auth_input);

    let envelope = Envelope {
        envelope_nonce: envelope_nonce.to_vec(),
        auth_tag,
    };

    StoreResult {
        envelope,
        client_public_key,
        masking_key,
        export_key,
    }
}

/// Recovers credentials from an envelope given the randomized password.
pub fn recover(
    config: &OpaqueConfig,
    randomized_pwd: &[u8],
    server_public_key: &[u8],
    envelope: &Envelope,
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
) -> Result<RecoverResult, &'static str> {
    let suite = config.cipher_suite();
    let nonce = &envelope.envelope_nonce;

    let auth_key = suite.hkdf_expand(randomized_pwd, &concat(&[nonce, b"AuthKey"]), config.nh());
    let export_key =
        suite.hkdf_expand(randomized_pwd, &concat(&[nonce, b"ExportKey"]), config.nh());
    // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
    let seed = suite.hkdf_expand(randomized_pwd, &concat(&[nonce, b"PrivateKey"]), NN);

    let key_pair = suite.derive_ake_key_pair(&seed);
    let client_sk = key_pair.private_key;
    let client_public_key = key_pair.public_key;

    let cleartext = CleartextCredentials::create(
        server_public_key,
        &client_public_key,
        server_identity,
        client_identity,
    );

    let auth_input = concat(&[nonce, &cleartext.serialize()]);
    let expected_tag = suite.hmac(&auth_key, &auth_input);

    if !ct_eq(&expected_tag, &envelope.auth_tag) {
        return Err("Authentication failed");
    }

    Ok(RecoverResult {
        client_private_key: client_sk,
        client_public_key,
        cleartext_credentials: cleartext,
        export_key,
    })
}
