//! Boundary tests for `KE2::deserialize`.
//!
//! This parser had no callers in `src/` and no tests. It is the public wire parser for the most
//! attacker-controlled message in the protocol — everything in KE2 arrives from the network before
//! any MAC has been checked — so its length handling is the whole of its safety. All of its
//! indexing is unchecked slicing after a single `data.len() < expected_len` guard, which means a
//! wrong constant or a dropped term in `expected_len` turns directly into a panic on hostile
//! input rather than an `Err`.
//!
//! Every suite is covered because `expected_len` is built from five per-suite size constants, and
//! an error in any one of them shows up only on the suites where that constant differs.

use hofmann_rfc::opaque::config::{OpaqueCipherSuite, OpaqueConfig, NN};
use hofmann_rfc::opaque::model::KE2;

fn suites() -> Vec<(&'static str, OpaqueCipherSuite)> {
    vec![
        ("P256_SHA256", OpaqueCipherSuite::from_name("P256_SHA256")),
        ("P384_SHA384", OpaqueCipherSuite::from_name("P384_SHA384")),
        ("P521_SHA512", OpaqueCipherSuite::from_name("P521_SHA512")),
        (
            "RISTRETTO255_SHA512",
            OpaqueCipherSuite::from_name("RISTRETTO255_SHA512"),
        ),
    ]
}

fn config_for(suite: OpaqueCipherSuite) -> OpaqueConfig {
    OpaqueConfig::with_argon2id(suite, b"ke2-deserialize-test".to_vec(), 1024, 1, 1)
}

fn expected_len(config: &OpaqueConfig) -> usize {
    config.noe() + NN + config.masked_response_size() + NN + config.npk() + config.nm()
}

/// A KE2 of exactly the right length must parse, and each field must land at its own offset with
/// its own length. Without this the rejection tests below would all pass against a parser that
/// refused everything.
#[test]
fn exact_length_input_parses_into_correctly_sized_fields() {
    for (name, suite) in suites() {
        let config = config_for(suite);
        let len = expected_len(&config);
        // Position-dependent bytes, so a transposed or overlapping slice is visible rather than
        // hidden behind a uniform fill.
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let ke2 = KE2::deserialize(&config, &data)
            .unwrap_or_else(|e| panic!("{name}: exact-length KE2 must parse, got {e}"));

        assert_eq!(
            ke2.credential_response.evaluated_element.len(),
            config.noe(),
            "{name}: evaluated_element length"
        );
        assert_eq!(
            ke2.credential_response.masking_nonce.len(),
            NN,
            "{name}: masking_nonce length"
        );
        assert_eq!(
            ke2.credential_response.masked_response.len(),
            config.masked_response_size(),
            "{name}: masked_response length"
        );
        assert_eq!(ke2.server_nonce.len(), NN, "{name}: server_nonce length");
        assert_eq!(
            ke2.server_ake_public_key.len(),
            config.npk(),
            "{name}: server_ake_public_key length"
        );
        assert_eq!(
            ke2.server_mac.len(),
            config.nm(),
            "{name}: server_mac length"
        );

        // Fields must be contiguous and in order: concatenating them reproduces the input.
        let mut rebuilt = Vec::with_capacity(len);
        rebuilt.extend_from_slice(&ke2.credential_response.evaluated_element);
        rebuilt.extend_from_slice(&ke2.credential_response.masking_nonce);
        rebuilt.extend_from_slice(&ke2.credential_response.masked_response);
        rebuilt.extend_from_slice(&ke2.server_nonce);
        rebuilt.extend_from_slice(&ke2.server_ake_public_key);
        rebuilt.extend_from_slice(&ke2.server_mac);
        assert_eq!(
            rebuilt, data,
            "{name}: fields must partition the input in order"
        );
    }
}

/// One byte short must be an `Err`, not a panic. This is the exact boundary of the only length
/// check in the function.
#[test]
fn one_byte_short_is_rejected() {
    for (name, suite) in suites() {
        let config = config_for(suite);
        let data = vec![0u8; expected_len(&config) - 1];

        assert!(
            KE2::deserialize(&config, &data).is_err(),
            "{name}: a KE2 one byte short must be rejected"
        );
    }
}

/// Every truncation, not just the boundary one. A parser that checked only some of its five
/// offsets would panic somewhere in this range instead of returning `Err`.
#[test]
fn every_truncation_is_rejected_without_panicking() {
    for (name, suite) in suites() {
        let config = config_for(suite);
        let len = expected_len(&config);

        for short_len in 0..len {
            let data = vec![0xAAu8; short_len];
            assert!(
                KE2::deserialize(&config, &data).is_err(),
                "{name}: {short_len} of {len} bytes must be rejected"
            );
        }
    }
}

/// Trailing bytes are accepted and ignored — the check is `<`, not `!=`. Pinned rather than
/// changed: KE2 is a fixed-width message with no trailer, so a stricter parser would be
/// defensible, but that is a deliberate protocol decision and this records the current contract
/// so a change to it is visible.
#[test]
fn trailing_bytes_are_ignored_rather_than_rejected() {
    for (name, suite) in suites() {
        let config = config_for(suite);
        let len = expected_len(&config);
        let mut data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let exact = data.clone();
        data.extend_from_slice(&[0xFF; 64]);

        let from_padded = KE2::deserialize(&config, &data)
            .unwrap_or_else(|e| panic!("{name}: padded KE2 currently parses, got {e}"));
        let from_exact = KE2::deserialize(&config, &exact)
            .unwrap_or_else(|e| panic!("{name}: exact KE2 must parse, got {e}"));

        assert_eq!(
            from_padded.server_mac, from_exact.server_mac,
            "{name}: trailing bytes must not shift the parsed fields"
        );
    }
}

/// An empty input is the degenerate hostile case and must not index anything.
#[test]
fn empty_input_is_rejected() {
    for (name, suite) in suites() {
        let config = config_for(suite);
        assert!(
            KE2::deserialize(&config, &[]).is_err(),
            "{name}: empty input must be rejected"
        );
    }
}
