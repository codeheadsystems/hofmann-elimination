use crate::common::concat;
use crate::opaque::config::OpaqueCipherSuite;

/// Client blind: maps password to a group element and applies a random blinding factor.
///
/// Raises `InvalidInputError` if `HashToGroup(input)` returns the identity
/// element, per RFC 9497 §3.3.1.
pub fn blind(suite: &OpaqueCipherSuite, password: &[u8], blind_scalar: &[u8]) -> Vec<u8> {
    let oprf = suite.oprf_suite();
    let gs = oprf.group_spec();
    let h = gs.hash_to_group(password, oprf.hash_to_group_dst());
    assert!(
        !gs.is_identity_element(&h),
        "InvalidInputError: HashToGroup returned identity element (RFC 9497 §3.3.1)"
    );
    gs.scalar_multiply(blind_scalar, &h)
}

/// Server OPRF evaluation: multiplies the blinded element by the OPRF key.
pub fn blind_evaluate(
    suite: &OpaqueCipherSuite,
    oprf_key: &[u8],
    blinded_element: &[u8],
) -> Vec<u8> {
    suite
        .oprf_suite()
        .group_spec()
        .scalar_multiply(oprf_key, blinded_element)
}

/// Client OPRF finalize: unblinds the evaluated element and hashes to produce OPRF output.
pub fn finalize(
    suite: &OpaqueCipherSuite,
    password: &[u8],
    blind_scalar: &[u8],
    evaluated_element: &[u8],
) -> Vec<u8> {
    suite
        .oprf_suite()
        .finalize(password, blind_scalar, evaluated_element)
}

/// Server: derives per-credential OPRF key from oprf_seed and credential identifier.
pub fn derive_oprf_key(
    suite: &OpaqueCipherSuite,
    oprf_seed: &[u8],
    credential_identifier: &[u8],
) -> Vec<u8> {
    let info = concat(&[credential_identifier, b"OprfKey"]);
    let seed = suite.hkdf_expand(oprf_seed, &info, suite.nok());
    suite
        .oprf_suite()
        .derive_key_pair(&seed, b"OPAQUE-DeriveKeyPair")
}
