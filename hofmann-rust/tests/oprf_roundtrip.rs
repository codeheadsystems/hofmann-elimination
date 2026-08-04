use hofmann_rfc::oprf::{CurveHashSuite, OprfCipherSuite};

fn run_oprf_roundtrip(suite: CurveHashSuite) {
    let oprf = OprfCipherSuite::new(suite);
    let mut rng = rand::rng();

    // Server: derive key pair
    let mut seed = vec![0u8; 32];
    rng.fill_bytes(&mut seed);
    use rand_core::Rng;
    let server_key = oprf.derive_key_pair(&seed, b"test-info");

    // Client: blind
    let input = b"sensitive-data";
    let blind = oprf.random_scalar(&mut rng);
    let gs = oprf.group_spec();
    let hashed = gs.hash_to_group(input, oprf.hash_to_group_dst());
    let blinded_element = gs.scalar_multiply(&blind, &hashed).unwrap();

    // Server: evaluate
    let evaluated_element = gs.scalar_multiply(&server_key, &blinded_element).unwrap();

    // Client: finalize
    let output = oprf.finalize(input, &blind, &evaluated_element).unwrap();

    // Output should be deterministic for same input + key
    assert_eq!(output.len(), oprf.hash_output_length());

    // Verify: running the same input through again gives the same output
    let blind2 = oprf.random_scalar(&mut rng);
    let blinded2 = gs.scalar_multiply(&blind2, &hashed).unwrap();
    let evaluated2 = gs.scalar_multiply(&server_key, &blinded2).unwrap();
    let output2 = oprf.finalize(input, &blind2, &evaluated2).unwrap();

    assert_eq!(
        output, output2,
        "OPRF should be deterministic for same input+key"
    );

    // Different input should give different output
    let other_input = b"different-data";
    let hashed_other = gs.hash_to_group(other_input, oprf.hash_to_group_dst());
    let blinded_other = gs.scalar_multiply(&blind, &hashed_other).unwrap();
    let evaluated_other = gs.scalar_multiply(&server_key, &blinded_other).unwrap();
    let output_other = oprf
        .finalize(other_input, &blind, &evaluated_other)
        .unwrap();

    assert_ne!(
        output, output_other,
        "Different inputs should give different outputs"
    );
}

#[test]
fn test_oprf_p256() {
    run_oprf_roundtrip(CurveHashSuite::P256Sha256);
}

#[test]
fn test_oprf_p384() {
    run_oprf_roundtrip(CurveHashSuite::P384Sha384);
}

#[test]
fn test_oprf_p521() {
    run_oprf_roundtrip(CurveHashSuite::P521Sha512);
}

#[test]
fn test_oprf_ristretto255() {
    run_oprf_roundtrip(CurveHashSuite::Ristretto255Sha512);
}

/// A malformed or identity element must return `Err` rather than panic, so a
/// server multiplying its secret key by an attacker-supplied element cannot be
/// crashed by a malicious request.
fn assert_scalar_multiply_rejects_bad_input(suite: CurveHashSuite) {
    let oprf = OprfCipherSuite::new(suite);
    let gs = oprf.group_spec();
    let mut rng = rand::rng();
    let key = oprf.random_scalar(&mut rng);

    // Wrong-length / non-canonical encoding.
    assert!(
        gs.scalar_multiply(&key, &[0xff; 5]).is_err(),
        "{:?}: malformed element must be rejected",
        suite
    );
    // The identity element (all-zero encoding of the element size).
    let identity = vec![0u8; gs.element_size()];
    assert!(
        gs.scalar_multiply(&key, &identity).is_err(),
        "{:?}: identity element must be rejected (RFC 9497 §2.1)",
        suite
    );
}

#[test]
fn test_scalar_multiply_rejects_bad_input_all_suites() {
    assert_scalar_multiply_rejects_bad_input(CurveHashSuite::P256Sha256);
    assert_scalar_multiply_rejects_bad_input(CurveHashSuite::P384Sha384);
    assert_scalar_multiply_rejects_bad_input(CurveHashSuite::P521Sha512);
    assert_scalar_multiply_rejects_bad_input(CurveHashSuite::Ristretto255Sha512);
}
