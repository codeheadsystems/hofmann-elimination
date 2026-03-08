use crate::common::concat;
use crate::opaque::config::OpaqueCipherSuite;

/// Client blind: maps password to a group element and applies a random blinding factor.
pub fn blind(suite: &OpaqueCipherSuite, password: &[u8], blind_scalar: &[u8]) -> Vec<u8> {
    let oprf = suite.oprf_suite();
    let h = oprf
        .group_spec()
        .hash_to_group(password, oprf.hash_to_group_dst());
    oprf.group_spec().scalar_multiply(blind_scalar, &h)
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
