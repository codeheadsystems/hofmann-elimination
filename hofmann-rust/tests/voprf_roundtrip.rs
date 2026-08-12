//! VOPRF and POPRF client/server round trips across every supported suite.
//!
//! The Appendix A byte-level assertions live in the crate's own unit tests,
//! where the prover with fixed randomness is reachable. What is checked here is
//! the public API: that a client and server built from this crate agree, and —
//! more usefully — that the client refuses everything it should.

use hofmann_rfc::oprf::{
    CurveHashSuite, OprfCipherSuite, OprfMode, PoprfClient, PoprfServer, VerifiableProcessorDetail,
    VoprfClient, VoprfServer,
};

const SUITES: [CurveHashSuite; 4] = [
    CurveHashSuite::P256Sha256,
    CurveHashSuite::P384Sha384,
    CurveHashSuite::P521Sha512,
    CurveHashSuite::Ristretto255Sha512,
];

const SEED: &[u8] = b"a-fixed-seed-for-integration-tests--------------------------------";
const KEY_INFO: &[u8] = b"test key";

fn voprf_pair(curve: CurveHashSuite) -> OprfCipherSuite {
    OprfCipherSuite::new_with_mode(curve, OprfMode::Voprf)
}

fn poprf_pair(curve: CurveHashSuite) -> OprfCipherSuite {
    OprfCipherSuite::new_with_mode(curve, OprfMode::Poprf)
}

fn detail(suite: &OprfCipherSuite) -> VerifiableProcessorDetail {
    VerifiableProcessorDetail::derive_from_seed(suite, SEED, KEY_INFO, "test-processor").unwrap()
}

#[test]
fn voprf_round_trips_on_every_suite() {
    for curve in SUITES {
        let suite = voprf_pair(curve);
        let server = VoprfServer::new(&suite, detail(&suite)).unwrap();
        let client = VoprfClient::new(&suite, server.public_key()).unwrap();
        let mut rng = rand::rng();

        let ctx = client.blind_batch(&[b"alpha", b"beta"], &mut rng).unwrap();
        let (evaluated, proof) = server
            .evaluate_batch(&ctx.blinded_elements, &mut rng)
            .unwrap();
        let outputs = client.finalize_batch(&ctx, &evaluated, &proof).unwrap();

        assert_eq!(outputs.len(), 2, "{}", suite.identifier());
        assert_ne!(outputs[0], outputs[1]);
        assert_eq!(outputs[0].len(), suite.hash_output_length());
    }
}

#[test]
fn voprf_is_deterministic_across_independent_blinds() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let server = VoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = VoprfClient::new(&suite, server.public_key()).unwrap();

    // Fresh randomness on each run, so what is asserted is that the blinding
    // cancels — not that the same blind was reused.
    let run = || {
        let ctx = client.blind_batch(&[b"stable"], &mut rand::rng()).unwrap();
        let (evaluated, proof) = server
            .evaluate_batch(&ctx.blinded_elements, &mut rand::rng())
            .unwrap();
        client.finalize_batch(&ctx, &evaluated, &proof).unwrap()[0].clone()
    };

    assert_eq!(run(), run());
}

/// Substituting one evaluated element for another honestly-produced one is what
/// the proof exists to catch; without it the client would unblind into an output
/// indistinguishable from correct.
#[test]
fn voprf_rejects_a_substituted_element() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let server = VoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = VoprfClient::new(&suite, server.public_key()).unwrap();
    let mut rng = rand::rng();

    let ctx = client.blind_batch(&[b"alpha", b"beta"], &mut rng).unwrap();
    let (mut evaluated, proof) = server
        .evaluate_batch(&ctx.blinded_elements, &mut rng)
        .unwrap();
    evaluated.swap(0, 1);

    assert!(client.finalize_batch(&ctx, &evaluated, &proof).is_err());
}

#[test]
fn voprf_rejects_a_server_using_a_different_key() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let honest = VoprfServer::new(&suite, detail(&suite)).unwrap();
    let impostor_detail = VerifiableProcessorDetail::derive_from_seed(
        &suite,
        b"a-different-seed-entirely",
        KEY_INFO,
        "p",
    )
    .unwrap();
    let impostor = VoprfServer::new(&suite, impostor_detail).unwrap();
    let client = VoprfClient::new(&suite, honest.public_key()).unwrap();
    let mut rng = rand::rng();

    let ctx = client.blind_batch(&[b"alpha"], &mut rng).unwrap();
    let (evaluated, proof) = impostor
        .evaluate_batch(&ctx.blinded_elements, &mut rng)
        .unwrap();

    assert!(client.finalize_batch(&ctx, &evaluated, &proof).is_err());
}

#[test]
fn voprf_rejects_a_short_response_before_verifying() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let server = VoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = VoprfClient::new(&suite, server.public_key()).unwrap();
    let mut rng = rand::rng();

    let ctx = client.blind_batch(&[b"alpha", b"beta"], &mut rng).unwrap();
    let (evaluated, proof) = server
        .evaluate_batch(&ctx.blinded_elements, &mut rng)
        .unwrap();

    let err = client
        .finalize_batch(&ctx, &evaluated[..1], &proof)
        .unwrap_err();
    assert!(err.contains("different number"));
}

#[test]
fn poprf_round_trips_on_every_suite() {
    for curve in SUITES {
        let suite = poprf_pair(curve);
        let server = PoprfServer::new(&suite, detail(&suite)).unwrap();
        let client = PoprfClient::new(&suite, server.public_key()).unwrap();
        let mut rng = rand::rng();

        let ctx = client
            .blind_batch(&[b"alpha", b"beta"], b"tenant-a", &mut rng)
            .unwrap();
        let (evaluated, proof) = server
            .evaluate_batch(&ctx.blinded_elements, b"tenant-a", &mut rng)
            .unwrap();
        let outputs = client.finalize_batch(&ctx, &evaluated, &proof).unwrap();

        assert_eq!(outputs.len(), 2, "{}", suite.identifier());
        assert_ne!(outputs[0], outputs[1]);
    }
}

#[test]
fn poprf_different_public_inputs_give_unrelated_outputs() {
    let suite = poprf_pair(CurveHashSuite::P256Sha256);
    let server = PoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = PoprfClient::new(&suite, server.public_key()).unwrap();

    let evaluate = |info: &[u8]| {
        let mut rng = rand::rng();
        let ctx = client.blind_batch(&[b"alpha"], info, &mut rng).unwrap();
        let (evaluated, proof) = server
            .evaluate_batch(&ctx.blinded_elements, info, &mut rng)
            .unwrap();
        client.finalize_batch(&ctx, &evaluated, &proof).unwrap()[0].clone()
    };

    assert_ne!(evaluate(b"tenant-a"), evaluate(b"tenant-b"));
}

/// Empty is a public input, not the absence of one. POPRF Finalize emits the
/// two-byte length prefix even when info is empty, where base mode omits the
/// field entirely — reusing the base-mode transcript here would silently compute
/// base mode and every self-consistent round trip would still pass.
#[test]
fn poprf_empty_public_input_is_real_and_distinct() {
    let suite = poprf_pair(CurveHashSuite::P256Sha256);
    let server = PoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = PoprfClient::new(&suite, server.public_key()).unwrap();

    let evaluate = |info: &[u8]| {
        let mut rng = rand::rng();
        let ctx = client.blind_batch(&[b"alpha"], info, &mut rng).unwrap();
        let (evaluated, proof) = server
            .evaluate_batch(&ctx.blinded_elements, info, &mut rng)
            .unwrap();
        client.finalize_batch(&ctx, &evaluated, &proof).unwrap()[0].clone()
    };

    let empty = evaluate(b"");
    assert!(!empty.is_empty());
    assert_ne!(empty, evaluate(b"tenant-a"));
}

/// The proof is graded against the tweaked key the client derived, which is what
/// binds the answer to the question actually asked.
#[test]
fn poprf_rejects_a_response_computed_under_a_different_public_input() {
    let suite = poprf_pair(CurveHashSuite::P256Sha256);
    let server = PoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = PoprfClient::new(&suite, server.public_key()).unwrap();
    let mut rng = rand::rng();

    let ctx = client
        .blind_batch(&[b"alpha"], b"asked-for", &mut rng)
        .unwrap();
    let (evaluated, proof) = server
        .evaluate_batch(&ctx.blinded_elements, b"served-instead", &mut rng)
        .unwrap();

    assert!(client.finalize_batch(&ctx, &evaluated, &proof).is_err());
}

// ── Mode separation ──────────────────────────────────────────────────────────

/// One secret must not serve two modes. The mode byte is in the DeriveKeyPair
/// tag, so the same seed already yields different keys — and the managers refuse
/// a detail derived for the other mode on top of that.
#[test]
fn a_detail_derived_for_one_mode_is_refused_by_the_other() {
    let voprf = voprf_pair(CurveHashSuite::P256Sha256);
    let poprf = poprf_pair(CurveHashSuite::P256Sha256);

    assert!(VoprfServer::new(&voprf, detail(&poprf)).is_err());
    assert!(PoprfServer::new(&poprf, detail(&voprf)).is_err());
}

#[test]
fn the_same_seed_gives_a_different_key_per_mode() {
    let voprf = voprf_pair(CurveHashSuite::P256Sha256);
    let poprf = poprf_pair(CurveHashSuite::P256Sha256);

    assert_ne!(detail(&voprf).public_key, detail(&poprf).public_key);
}

#[test]
fn a_base_mode_suite_is_refused_by_both_modes() {
    let base = OprfCipherSuite::new(CurveHashSuite::P256Sha256);
    let voprf = voprf_pair(CurveHashSuite::P256Sha256);
    let key = detail(&voprf).public_key.clone();

    assert!(VoprfClient::new(&base, &key).is_err());
    assert!(PoprfClient::new(&base, &key).is_err());
    assert!(VerifiableProcessorDetail::derive_from_seed(&base, SEED, KEY_INFO, "p").is_err());
}

/// A VOPRF-mode suite is not a POPRF-mode suite, even though both are verifiable.
#[test]
fn the_two_verifiable_modes_do_not_accept_each_others_suites() {
    let voprf = voprf_pair(CurveHashSuite::P256Sha256);
    let poprf = poprf_pair(CurveHashSuite::P256Sha256);
    let key = detail(&voprf).public_key.clone();

    assert!(PoprfClient::new(&voprf, &key).is_err());
    assert!(VoprfClient::new(&poprf, &detail(&poprf).public_key).is_err());
}

#[test]
fn an_identity_public_key_is_refused_at_construction() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let identity = vec![0u8; suite.element_size()];

    assert!(VoprfClient::new(&suite, &identity).is_err());
}

// ── Batch bounds ─────────────────────────────────────────────────────────────

#[test]
fn an_empty_batch_is_refused_on_both_sides() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let server = VoprfServer::new(&suite, detail(&suite)).unwrap();
    let client = VoprfClient::new(&suite, server.public_key()).unwrap();
    let mut rng = rand::rng();

    assert!(client.blind_batch(&[], &mut rng).is_err());
    assert!(server.evaluate_batch(&[], &mut rng).is_err());
}

#[test]
fn a_batch_over_the_configured_cap_is_refused() {
    let suite = voprf_pair(CurveHashSuite::P256Sha256);
    let server = VoprfServer::with_max_batch_size(&suite, detail(&suite), 2).unwrap();
    let client = VoprfClient::new(&suite, server.public_key()).unwrap();
    let mut rng = rand::rng();

    let ctx = client.blind_batch(&[b"a", b"b", b"c"], &mut rng).unwrap();

    assert!(server
        .evaluate_batch(&ctx.blinded_elements, &mut rng)
        .is_err());
}
