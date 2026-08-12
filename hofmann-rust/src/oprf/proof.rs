//! RFC 9497 §2.2 discrete-log-equality proofs, shared by VOPRF and POPRF.
//!
//! Every detail in this module is one a port can get wrong in a way that stays
//! self-consistent. A prover and verifier that agree on the wrong scalar order,
//! the wrong transcript field order, or on hashing the composite seed to a
//! scalar rather than plainly, interoperate perfectly with each other and fail
//! only against the RFC's Appendix A vectors. The tests assert proof *bytes*,
//! not just round trips, for that reason.

use crate::common::{concat, i2osp};
use crate::oprf::cipher_suite::OprfCipherSuite;
use crate::oprf::mode::OprfMode;

/// Encoding-level ceiling on the batch size.
///
/// The composite transcript writes the index as `I2OSP(i, 2)`, so this is what
/// the encoding can represent. It is not an operational cap — a batch this size
/// is well over a hundred thousand scalar multiplications — and the policy cap
/// belongs with the managers, where request size and tail latency govern.
pub const MAX_BATCH: usize = 65535;

/// A DLEQ proof: the challenge scalar and the response scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DleqProof {
    /// The challenge scalar, in the suite's canonical encoding.
    pub c: Vec<u8>,
    /// The response scalar, in the suite's canonical encoding.
    pub s: Vec<u8>,
}

impl DleqProof {
    /// Serializes as `SerializeScalar(c) || SerializeScalar(s)`, exactly `2 * Ns`
    /// bytes.
    ///
    /// The order is `c` then `s`, per §2.2.1's `return [c, s]` and the `Proof`
    /// field in the Appendix A vectors. Nothing in a round trip catches a
    /// reversal — a prover and verifier that agree on the wrong order
    /// interoperate perfectly.
    pub fn serialize(&self, suite: &OprfCipherSuite) -> Vec<u8> {
        let group = suite.group_spec();
        concat(&[
            &group.serialize_scalar(&self.c),
            &group.serialize_scalar(&self.s),
        ])
    }

    /// Parses a proof from its wire encoding.
    ///
    /// Both scalars go through `deserialize_scalar`, which rejects a
    /// non-canonical encoding. That is what stops the proof being malleable:
    /// without it `c` and `c + n` are distinct byte strings that verify
    /// identically.
    pub fn deserialize(suite: &OprfCipherSuite, bytes: &[u8]) -> Result<Self, &'static str> {
        let group = suite.group_spec();
        let ns = group.scalar_size();
        if bytes.len() != 2 * ns {
            return Err("proof must be exactly 2 * Ns bytes");
        }
        Ok(DleqProof {
            c: group.deserialize_scalar(&bytes[..ns])?,
            s: group.deserialize_scalar(&bytes[ns..])?,
        })
    }
}

fn validate_batch(c: &[Vec<u8>], d: &[Vec<u8>]) -> Result<(), &'static str> {
    if c.len() != d.len() {
        return Err("batch element lists must be the same length");
    }
    if c.is_empty() {
        return Err("batch must contain at least one element pair");
    }
    if c.len() > MAX_BATCH {
        return Err("batch exceeds the maximum encodable size");
    }
    Ok(())
}

/// Derives the `d_i` coefficient for each batch entry.
///
/// Two details are easy to get subtly wrong. First, `seed_dst` is transcript
/// *data*, length-prefixed like any other field — it is not used as a
/// domain-separation tag. Second, `seed` is the suite's plain hash of that
/// transcript, not a hash-to-scalar; only `d_i` is a hash-to-scalar, and it uses
/// the ordinary suite DST rather than any proof-specific tag.
fn coefficients(
    suite: &OprfCipherSuite,
    b: &[u8],
    c: &[Vec<u8>],
    d: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, &'static str> {
    validate_batch(c, d)?;

    let seed_dst = concat(&[b"Seed-", suite.context_string()]);
    let seed = suite.hash(&concat(&[
        &i2osp(b.len() as u32, 2),
        b,
        &i2osp(seed_dst.len() as u32, 2),
        &seed_dst,
    ]));

    let group = suite.group_spec();
    let mut out = Vec::with_capacity(c.len());
    for i in 0..c.len() {
        let transcript = concat(&[
            &i2osp(seed.len() as u32, 2),
            &seed,
            &i2osp(i as u32, 2),
            &i2osp(c[i].len() as u32, 2),
            &c[i],
            &i2osp(d[i].len() as u32, 2),
            &d[i],
            b"Composite",
        ]);
        out.push(group.hash_to_scalar(&transcript, suite.hash_to_scalar_dst()));
    }
    Ok(out)
}

struct Composites {
    m: Vec<u8>,
    z: Vec<u8>,
}

fn as_refs(items: &[Vec<u8>]) -> Vec<&[u8]> {
    items.iter().map(|v| v.as_slice()).collect()
}

/// Verifier-side fold (§2.2.2): accumulate both composites, having no key to
/// shortcut `Z` with.
fn compute_composites(
    suite: &OprfCipherSuite,
    b: &[u8],
    c: &[Vec<u8>],
    d: &[Vec<u8>],
) -> Result<Composites, &'static str> {
    let coeffs = coefficients(suite, b, c, d)?;
    let group = suite.group_spec();
    let coeff_refs = as_refs(&coeffs);
    Ok(Composites {
        m: group.linear_combination(&coeff_refs, &as_refs(c))?,
        z: group.linear_combination(&coeff_refs, &as_refs(d))?,
    })
}

/// Prover-side fold (§2.2.1): `Z = k * M` straight from the key, which is the
/// "fast" part.
fn compute_composites_fast(
    suite: &OprfCipherSuite,
    k: &[u8],
    b: &[u8],
    c: &[Vec<u8>],
    d: &[Vec<u8>],
) -> Result<Composites, &'static str> {
    let coeffs = coefficients(suite, b, c, d)?;
    let group = suite.group_spec();
    let m = group.linear_combination(&as_refs(&coeffs), &as_refs(c))?;
    let z = group.scalar_multiply(k, &m)?;
    Ok(Composites { m, z })
}

/// The challenge transcript, shared by prover and verifier so the two cannot
/// drift.
///
/// Note what is *not* in it: `A`, the generator. Binding comes instead from the
/// verifier recomputing `t2 = s*A + c*B` with its own `A`. A port that includes
/// the generator self-interoperates and fails every vector.
fn challenge(
    suite: &OprfCipherSuite,
    b: &[u8],
    composites: &Composites,
    t2: &[u8],
    t3: &[u8],
) -> Vec<u8> {
    let transcript = concat(&[
        &i2osp(b.len() as u32, 2),
        b,
        &i2osp(composites.m.len() as u32, 2),
        &composites.m,
        &i2osp(composites.z.len() as u32, 2),
        &composites.z,
        &i2osp(t2.len() as u32, 2),
        t2,
        &i2osp(t3.len() as u32, 2),
        t3,
        b"Challenge",
    ]);
    suite
        .group_spec()
        .hash_to_scalar(&transcript, suite.hash_to_scalar_dst())
}

/// RFC 9497 §2.2.1 `GenerateProof` with caller-supplied randomness.
///
/// Crate-private, deliberately. This exists to reproduce the fixed
/// `ProofRandomScalar` values in the Appendix A vectors, which cannot be reached
/// through the group's rejection sampler. `r` is the one input whose reuse or
/// bias hands over the server's long-term key, so no caller outside this crate
/// gets to supply it — and callers inside it go through [`VoprfServer`] and
/// [`PoprfServer`], which never do.
///
/// [`VoprfServer`]: crate::oprf::VoprfServer
/// [`PoprfServer`]: crate::oprf::PoprfServer
pub(crate) fn generate_proof_with_randomness(
    suite: &OprfCipherSuite,
    k: &[u8],
    b: &[u8],
    c: &[Vec<u8>],
    d: &[Vec<u8>],
    r: &[u8],
) -> Result<DleqProof, &'static str> {
    suite.assert_mode(&[OprfMode::Voprf, OprfMode::Poprf])?;
    let group = suite.group_spec();
    if group.scalar_is_zero(r) {
        return Err("proof randomness must be a scalar in [1, n-1]");
    }

    let composites = compute_composites_fast(suite, k, b, c, d)?;

    let t2 = group.scalar_multiply_generator(r);
    let t3 = group.scalar_multiply(r, &composites.m)?;

    let ch = challenge(suite, b, &composites, &t2, &t3);
    // The scalar field does the reduction, which matters: r - c*k is negative
    // for the common case c*k > r, and a signed intermediate does not encode.
    let s = group.scalar_sub(r, &group.scalar_mul(&ch, k));

    Ok(DleqProof { c: ch, s })
}

/// RFC 9497 §2.2.1 `GenerateProof` with fresh randomness.
///
/// Crate-private: a client never proves, and this crate's own servers are the
/// only callers. A public prover would be a way for anything holding this
/// crate's types to impersonate a server.
pub(crate) fn generate_proof(
    suite: &OprfCipherSuite,
    k: &[u8],
    b: &[u8],
    c: &[Vec<u8>],
    d: &[Vec<u8>],
    rng: &mut dyn rand_core::CryptoRng,
) -> Result<DleqProof, &'static str> {
    let r = suite.group_spec().random_scalar(rng);
    generate_proof_with_randomness(suite, k, b, c, d, &r)
}

/// RFC 9497 §2.2.2 `VerifyProof`.
///
/// Crate-private for symmetry with the prover: callers verify by going through
/// [`VoprfClient::finalize_batch`] or [`PoprfClient::finalize_batch`], which own
/// the element ordering — and getting that ordering wrong is a bug that
/// round-trips against itself.
///
/// [`VoprfClient::finalize_batch`]: crate::oprf::VoprfClient::finalize_batch
/// [`PoprfClient::finalize_batch`]: crate::oprf::PoprfClient::finalize_batch
///
/// Returns a bool rather than a `Result` for every attacker-influenced failure,
/// and deliberately so. A proof that fails because an element computed to the
/// identity, or because a supplied element was not a valid encoding, must be
/// indistinguishable to the caller from one that simply did not verify — an
/// error that named the cause would let a remote party tell those cases apart,
/// and would push callers into rendering a bad proof as a server error rather
/// than a rejected response.
///
/// A length-mismatched or empty batch returns false too, but callers are
/// expected to have checked the response length first and to say so themselves;
/// see the managers.
pub(crate) fn verify_proof(
    suite: &OprfCipherSuite,
    b: &[u8],
    c: &[Vec<u8>],
    d: &[Vec<u8>],
    proof: &DleqProof,
) -> bool {
    if suite
        .assert_mode(&[OprfMode::Voprf, OprfMode::Poprf])
        .is_err()
    {
        return false;
    }
    let group = suite.group_spec();
    let composites = match compute_composites(suite, b, c, d) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Neither term may be computed separately: a remote party can set s = 0,
    // which makes s*G the identity, and the identity has no Ne-byte encoding.
    let scalars: Vec<&[u8]> = vec![&proof.s, &proof.c];
    let generator = group.generator();
    let t2 = match group.linear_combination(&scalars, &[&generator, b]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let t3 = match group.linear_combination(&scalars, &[&composites.m, &composites.z]) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let expected = challenge(suite, b, &composites, &t2, &t3);
    // Compared as fixed-width encodings without an early exit. No known attack
    // needs this — each trial c yields a fresh, unrelated expected value — but
    // it costs nothing.
    ct_eq(
        &group.serialize_scalar(&expected),
        &group.serialize_scalar(&proof.c),
    )
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf::test_vectors::{load, ModeName};
    use crate::oprf::{CurveHashSuite, OprfMode};

    const SUITES: [(&str, CurveHashSuite); 4] = [
        ("P256-SHA256", CurveHashSuite::P256Sha256),
        ("P384-SHA384", CurveHashSuite::P384Sha384),
        ("P521-SHA512", CurveHashSuite::P521Sha512),
        ("ristretto255-SHA512", CurveHashSuite::Ristretto255Sha512),
    ];

    /// The scalar a proof is generated under: the server key for VOPRF, the key
    /// tweaked by the public input for POPRF.
    fn proof_key(suite: &OprfCipherSuite, sk: &[u8], info: Option<&[u8]>) -> Vec<u8> {
        match info {
            None => sk.to_vec(),
            Some(info) => {
                let m = crate::oprf::public_input::to_scalar(suite, info).unwrap();
                suite.group_spec().scalar_add(sk, &m)
            }
        }
    }

    /// Byte-exact reproduction of the RFC's own `Proof` field.
    ///
    /// This is the assertion that catches a self-consistent mistake: a prover and
    /// verifier that agree on the wrong scalar order or the wrong transcript
    /// interoperate perfectly and fail only here.
    #[test]
    fn appendix_a_proof_bytes_reproduce() {
        for (rfc_name, curve) in SUITES {
            for (mode_name, mode) in [
                (ModeName::Voprf, OprfMode::Voprf),
                (ModeName::Poprf, OprfMode::Poprf),
            ] {
                let suite = OprfCipherSuite::new_with_mode(curve, mode);
                let vectors = load(rfc_name, mode_name);
                let group = suite.group_spec();

                for (index, v) in vectors.vectors.iter().enumerate() {
                    let k = proof_key(&suite, &vectors.sk_sm, v.info.as_deref());
                    let b = group.scalar_multiply_generator(&k);
                    // POPRF proves over the lists reversed, because the server
                    // computes evaluated = t^-1 * blinded rather than t * blinded.
                    let (c, d) = if mode == OprfMode::Poprf {
                        (&v.evaluation_elements, &v.blinded_elements)
                    } else {
                        (&v.blinded_elements, &v.evaluation_elements)
                    };

                    let proof = generate_proof_with_randomness(
                        &suite,
                        &k,
                        &b,
                        c,
                        d,
                        v.proof_random_scalar.as_ref().unwrap(),
                    )
                    .unwrap();

                    assert_eq!(
                        proof.serialize(&suite),
                        *v.proof.as_ref().unwrap(),
                        "{rfc_name}/{mode_name:?} vector {index} proof bytes"
                    );
                }
            }
        }
    }

    #[test]
    fn appendix_a_proofs_verify() {
        for (rfc_name, curve) in SUITES {
            for (mode_name, mode) in [
                (ModeName::Voprf, OprfMode::Voprf),
                (ModeName::Poprf, OprfMode::Poprf),
            ] {
                let suite = OprfCipherSuite::new_with_mode(curve, mode);
                let vectors = load(rfc_name, mode_name);
                let group = suite.group_spec();

                for (index, v) in vectors.vectors.iter().enumerate() {
                    let k = proof_key(&suite, &vectors.sk_sm, v.info.as_deref());
                    let b = group.scalar_multiply_generator(&k);
                    let (c, d) = if mode == OprfMode::Poprf {
                        (&v.evaluation_elements, &v.blinded_elements)
                    } else {
                        (&v.blinded_elements, &v.evaluation_elements)
                    };
                    let proof = DleqProof::deserialize(&suite, v.proof.as_ref().unwrap()).unwrap();

                    assert!(
                        verify_proof(&suite, &b, c, d, &proof),
                        "{rfc_name}/{mode_name:?} vector {index} did not verify"
                    );
                }
            }
        }
    }

    /// `(secret key, public key, first element list, second element list)`.
    type Batch = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>);

    fn batch(suite: &OprfCipherSuite, n: usize) -> Batch {
        let group = suite.group_spec();
        let mut rng = rand::rng();
        let k = group.random_scalar(&mut rng);
        let b = group.scalar_multiply_generator(&k);
        let mut c = Vec::new();
        let mut d = Vec::new();
        for i in 0..n {
            let element = group.hash_to_group(&[i as u8], suite.hash_to_group_dst());
            d.push(group.scalar_multiply(&k, &element).unwrap());
            c.push(element);
        }
        (k, b, c, d)
    }

    /// The vectors only cover batch sizes 1 and 2, so the composite index
    /// encoding beyond that is otherwise untested.
    #[test]
    fn round_trips_at_batch_sizes_beyond_the_vectors() {
        let suite = OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Voprf);
        let mut rng = rand::rng();
        for n in [1usize, 2, 3, 8, 17] {
            let (k, b, c, d) = batch(&suite, n);
            let proof = generate_proof(&suite, &k, &b, &c, &d, &mut rng).unwrap();
            assert!(verify_proof(&suite, &b, &c, &d, &proof), "batch of {n}");
        }
    }

    #[test]
    fn rejects_a_proof_against_the_wrong_public_key() {
        let suite = OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Voprf);
        let mut rng = rand::rng();
        let (k, b, c, d) = batch(&suite, 2);
        let proof = generate_proof(&suite, &k, &b, &c, &d, &mut rng).unwrap();
        let other = suite
            .group_spec()
            .scalar_multiply_generator(&suite.group_spec().random_scalar(&mut rng));

        assert!(!verify_proof(&suite, &other, &c, &d, &proof));
    }

    /// The batch is bound as an ordered list; the composite index is what does it.
    #[test]
    fn rejects_a_reordered_batch() {
        let suite = OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Voprf);
        let mut rng = rand::rng();
        let (k, b, c, d) = batch(&suite, 2);
        let proof = generate_proof(&suite, &k, &b, &c, &d, &mut rng).unwrap();
        let swapped_c = vec![c[1].clone(), c[0].clone()];
        let swapped_d = vec![d[1].clone(), d[0].clone()];

        assert!(!verify_proof(&suite, &b, &swapped_c, &swapped_d, &proof));
    }

    #[test]
    fn rejects_a_bit_flipped_proof() {
        let suite = OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Voprf);
        let mut rng = rand::rng();
        let (k, b, c, d) = batch(&suite, 2);
        let mut bytes = generate_proof(&suite, &k, &b, &c, &d, &mut rng)
            .unwrap()
            .serialize(&suite);
        bytes[0] ^= 0x01;

        match DleqProof::deserialize(&suite, &bytes) {
            // A flipped high byte may push c out of canonical range, which is
            // also a rejection — either outcome is a refusal, which is the point.
            Err(_) => {}
            Ok(proof) => assert!(!verify_proof(&suite, &b, &c, &d, &proof)),
        }
    }

    #[test]
    fn refuses_to_prove_or_verify_under_a_base_mode_suite() {
        let base = OprfCipherSuite::new(CurveHashSuite::P256Sha256);
        let voprf = OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Voprf);
        let mut rng = rand::rng();
        let (k, b, c, d) = batch(&voprf, 1);
        let proof = generate_proof(&voprf, &k, &b, &c, &d, &mut rng).unwrap();

        assert!(generate_proof(&base, &k, &b, &c, &d, &mut rng).is_err());
        assert!(!verify_proof(&base, &b, &c, &d, &proof));
    }

    /// Without the canonical range check, `c` and `c + n` are distinct byte
    /// strings that verify identically. Every positive vector passes either way,
    /// so this is the only thing asserting it.
    /// The encoding of exactly *n*, in the suite's own scalar convention.
    ///
    /// `group_order()` is big-endian at the curve's natural width, which is not
    /// always Ns — P-521's 66-byte order arrives in a 72-byte container — so it
    /// is right-aligned to Ns before use, and reversed for ristretto255.
    fn order_encoding(suite: &OprfCipherSuite) -> Vec<u8> {
        let group = suite.group_spec();
        let ns = group.scalar_size();
        let order = group.group_order();
        let mut bytes = order[order.len() - ns..].to_vec();
        if suite.identifier().starts_with("ristretto255") {
            bytes.reverse();
        }
        bytes
    }

    /// Without the canonical range check, `c` and `c + n` are distinct byte
    /// strings that verify identically. Every positive vector passes either way,
    /// so this is the only thing asserting it.
    #[test]
    fn rejects_a_non_canonical_scalar_in_a_proof() {
        for (_, curve) in SUITES {
            let suite = OprfCipherSuite::new_with_mode(curve, OprfMode::Voprf);
            let ns = suite.group_spec().scalar_size();
            let at_order = order_encoding(&suite);
            assert_eq!(at_order.len(), ns);
            let bytes = [at_order.clone(), at_order].concat();

            assert!(
                DleqProof::deserialize(&suite, &bytes).is_err(),
                "{} accepted a scalar equal to the group order",
                suite.identifier()
            );
        }
    }

    /// The boundary from the other side, so the check is not simply refusing
    /// everything. `n - 1` is the largest canonical scalar and must parse.
    #[test]
    fn accepts_the_largest_canonical_scalar() {
        for (_, curve) in SUITES {
            let suite = OprfCipherSuite::new_with_mode(curve, OprfMode::Voprf);
            let mut bytes = order_encoding(&suite);
            if suite.identifier().starts_with("ristretto255") {
                bytes[0] -= 1; // little-endian least significant byte
            } else {
                let last = bytes.len() - 1;
                bytes[last] -= 1;
            }
            let proof_bytes = [bytes.clone(), bytes].concat();

            assert!(
                DleqProof::deserialize(&suite, &proof_bytes).is_ok(),
                "{} rejected n-1, which is canonical",
                suite.identifier()
            );
        }
    }

    #[test]
    fn rejects_a_wrong_length_proof() {
        let suite = OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Voprf);
        assert!(DleqProof::deserialize(&suite, &[0u8; 63]).is_err());
    }
}
