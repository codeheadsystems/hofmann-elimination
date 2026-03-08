use hofmann_rfc::oprf::{CurveHashSuite, OprfCipherSuite};

fn run_oprf_roundtrip(suite: CurveHashSuite) {
    let oprf = OprfCipherSuite::new(suite);
    let mut rng = rand::thread_rng();

    // Server: derive key pair
    let mut seed = vec![0u8; 32];
    rng.fill_bytes(&mut seed);
    use rand::RngCore;
    let server_key = oprf.derive_key_pair(&seed, b"test-info");

    // Client: blind
    let input = b"sensitive-data";
    let blind = oprf.random_scalar(&mut rng);
    let gs = oprf.group_spec();
    let hashed = gs.hash_to_group(input, oprf.hash_to_group_dst());
    let blinded_element = gs.scalar_multiply(&blind, &hashed);

    // Server: evaluate
    let evaluated_element = gs.scalar_multiply(&server_key, &blinded_element);

    // Client: finalize
    let output = oprf.finalize(input, &blind, &evaluated_element);

    // Output should be deterministic for same input + key
    assert_eq!(output.len(), oprf.hash_output_length());

    // Verify: running the same input through again gives the same output
    let blind2 = oprf.random_scalar(&mut rng);
    let blinded2 = gs.scalar_multiply(&blind2, &hashed);
    let evaluated2 = gs.scalar_multiply(&server_key, &blinded2);
    let output2 = oprf.finalize(input, &blind2, &evaluated2);

    assert_eq!(
        output, output2,
        "OPRF should be deterministic for same input+key"
    );

    // Different input should give different output
    let other_input = b"different-data";
    let hashed_other = gs.hash_to_group(other_input, oprf.hash_to_group_dst());
    let blinded_other = gs.scalar_multiply(&blind, &hashed_other);
    let evaluated_other = gs.scalar_multiply(&server_key, &blinded_other);
    let output_other = oprf.finalize(other_input, &blind, &evaluated_other);

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
