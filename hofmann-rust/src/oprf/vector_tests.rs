//! End-to-end RFC 9497 Appendix A conformance for all three modes.
//!
//! These live inside the crate rather than in `tests/` because they drive the
//! client from the vectors' own fixed blinds, which means constructing a context
//! directly rather than through `blind_batch`. What is asserted is the whole
//! chain: this client, given the RFC's blinds and the RFC's server key, verifies
//! the RFC's proof and produces the RFC's `Output`. An implementation that is
//! merely self-consistent fails at the last step.

use crate::oprf::model::{tweaked_public_key, PoprfClientContext, VoprfClientContext};
use crate::oprf::test_vectors::{load, ModeName};
use crate::oprf::{CurveHashSuite, OprfCipherSuite, OprfMode, PoprfClient, VoprfClient};

const SUITES: [(&str, CurveHashSuite); 4] = [
    ("P256-SHA256", CurveHashSuite::P256Sha256),
    ("P384-SHA384", CurveHashSuite::P384Sha384),
    ("P521-SHA512", CurveHashSuite::P521Sha512),
    ("ristretto255-SHA512", CurveHashSuite::Ristretto255Sha512),
];

const MODES: [(ModeName, OprfMode); 3] = [
    (ModeName::Oprf, OprfMode::Oprf),
    (ModeName::Voprf, OprfMode::Voprf),
    (ModeName::Poprf, OprfMode::Poprf),
];

/// The mode byte is in the `DeriveKeyPair` DST, so one seed gives a different
/// key in each mode — which is what makes "one key per mode" enforceable rather
/// than merely advised. The vectors record it directly: ristretto255's base-mode
/// `skSm` begins `5ebc` where its VOPRF one begins `e6f7`.
#[test]
fn derive_key_pair_matches_every_suite_and_mode() {
    for (rfc_name, curve) in SUITES {
        for (mode_name, mode) in MODES {
            let suite = OprfCipherSuite::new_with_mode(curve, mode);
            let vectors = load(rfc_name, mode_name);

            let derived = suite.derive_key_pair(&vectors.seed, &vectors.key_info);

            assert_eq!(
                derived, vectors.sk_sm,
                "{rfc_name}/{mode_name:?} derived key does not match skSm"
            );
        }
    }
}

#[test]
fn one_seed_gives_three_different_keys() {
    for (rfc_name, curve) in SUITES {
        let base = load(rfc_name, ModeName::Oprf);
        let keys: Vec<Vec<u8>> = MODES
            .iter()
            .map(|(_, mode)| {
                OprfCipherSuite::new_with_mode(curve, *mode)
                    .derive_key_pair(&base.seed, &base.key_info)
            })
            .collect();

        assert_ne!(keys[0], keys[1], "{rfc_name}: OPRF and VOPRF keys collide");
        assert_ne!(keys[1], keys[2], "{rfc_name}: VOPRF and POPRF keys collide");
        assert_ne!(keys[0], keys[2], "{rfc_name}: OPRF and POPRF keys collide");
    }
}

/// The vectors carry `pkSm` for the verifiable modes; it must be what the
/// group derives from `skSm`, or a client pinning the published key would
/// reject a correct server.
#[test]
fn public_keys_match_the_vectors() {
    for (rfc_name, curve) in SUITES {
        for mode_name in [ModeName::Voprf, ModeName::Poprf] {
            let mode = if mode_name == ModeName::Voprf {
                OprfMode::Voprf
            } else {
                OprfMode::Poprf
            };
            let suite = OprfCipherSuite::new_with_mode(curve, mode);
            let vectors = load(rfc_name, mode_name);
            let Some(expected) = vectors.pk_sm.as_ref() else {
                continue;
            };

            let derived = suite.group_spec().scalar_multiply_generator(&vectors.sk_sm);

            assert_eq!(&derived, expected, "{rfc_name}/{mode_name:?} public key");
        }
    }
}

#[test]
fn voprf_reproduces_every_appendix_a_output() {
    for (rfc_name, curve) in SUITES {
        let suite = OprfCipherSuite::new_with_mode(curve, OprfMode::Voprf);
        let vectors = load(rfc_name, ModeName::Voprf);
        let group = suite.group_spec();
        let public_key = group.scalar_multiply_generator(&vectors.sk_sm);
        let client = VoprfClient::new(&suite, &public_key).unwrap();

        for (index, v) in vectors.vectors.iter().enumerate() {
            // The blinded elements this client would produce from the vector's
            // fixed blinds must be the RFC's, before anything downstream matters.
            for (i, input) in v.inputs.iter().enumerate() {
                let hashed = group.hash_to_group(input, suite.hash_to_group_dst());
                let blinded = group.scalar_multiply(&v.blinds[i], &hashed).unwrap();
                assert_eq!(
                    blinded, v.blinded_elements[i],
                    "{rfc_name} vector {index} element {i} blinded"
                );
            }

            let ctx = VoprfClientContext {
                inputs: v.inputs.clone(),
                blinds: v.blinds.clone(),
                blinded_elements: v.blinded_elements.clone(),
            };
            let outputs = client
                .finalize_batch(&ctx, &v.evaluation_elements, v.proof.as_ref().unwrap())
                .unwrap_or_else(|e| panic!("{rfc_name} vector {index}: {e}"));

            assert_eq!(outputs, v.outputs, "{rfc_name} vector {index} outputs");
            assert_eq!(outputs.len(), v.batch_size);
        }
    }
}

#[test]
fn poprf_reproduces_every_appendix_a_output() {
    for (rfc_name, curve) in SUITES {
        let suite = OprfCipherSuite::new_with_mode(curve, OprfMode::Poprf);
        let vectors = load(rfc_name, ModeName::Poprf);
        let group = suite.group_spec();
        let public_key = group.scalar_multiply_generator(&vectors.sk_sm);
        let client = PoprfClient::new(&suite, &public_key).unwrap();

        for (index, v) in vectors.vectors.iter().enumerate() {
            let info = v.info.as_ref().unwrap();
            let ctx = PoprfClientContext {
                inputs: v.inputs.clone(),
                blinds: v.blinds.clone(),
                blinded_elements: v.blinded_elements.clone(),
                info: info.clone(),
                tweaked_key: tweaked_public_key(&suite, &public_key, info).unwrap(),
            };

            let outputs = client
                .finalize_batch(&ctx, &v.evaluation_elements, v.proof.as_ref().unwrap())
                .unwrap_or_else(|e| panic!("{rfc_name} vector {index}: {e}"));

            assert_eq!(outputs, v.outputs, "{rfc_name} vector {index} outputs");
        }
    }
}

/// Base mode is untouched by the mode threading, and this is the check that says
/// so against the spec rather than against itself.
#[test]
fn base_mode_still_reproduces_its_appendix_a_outputs() {
    for (rfc_name, curve) in SUITES {
        let suite = OprfCipherSuite::new(curve);
        let vectors = load(rfc_name, ModeName::Oprf);

        for (index, v) in vectors.vectors.iter().enumerate() {
            for (i, input) in v.inputs.iter().enumerate() {
                let evaluated = &v.evaluation_elements[i];
                let output = suite.finalize(input, &v.blinds[i], evaluated).unwrap();
                assert_eq!(
                    output, v.outputs[i],
                    "{rfc_name} vector {index} element {i}"
                );
            }
        }
    }
}
