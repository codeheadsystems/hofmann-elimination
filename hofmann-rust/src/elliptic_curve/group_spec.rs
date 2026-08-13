/// Abstraction over a cryptographic group for use in RFC 9497 OPRF and
/// RFC 9807 OPAQUE.
///
/// Implementations bundle all per-group details — curve/field arithmetic,
/// hash-to-group, serialization — into one type. Adding a new cipher suite
/// only requires implementing this trait.
///
/// # Encoding conventions
///
/// - **Group elements** cross the interface as `Vec<u8>` in serialized
///   canonical form (compressed SEC1 for Weierstrass curves, 32-byte
///   canonical encoding for ristretto255).
/// - **Scalars** cross as `Vec<u8>` in the suite's native byte order:
///   big-endian for Weierstrass curves, little-endian for ristretto255.
///
/// # Implementors
///
/// - [`super::WeierstrassGroupSpec`] — P-256, P-384, P-521
/// - [`super::Ristretto255GroupSpec`] — ristretto255 (RFC 9496)
pub trait GroupSpec: Send + Sync {
    /// Returns the prime group order *n* as big-endian bytes.
    fn group_order(&self) -> Vec<u8>;

    /// Returns the size of a serialized group element in bytes (Ne).
    ///
    /// | Curve | Ne |
    /// |---|---|
    /// | P-256 | 33 |
    /// | P-384 | 49 |
    /// | P-521 | 67 |
    /// | ristretto255 | 32 |
    fn element_size(&self) -> usize;

    /// Returns the size of a serialized scalar in bytes (Ns).
    fn scalar_size(&self) -> usize;

    /// Maps an arbitrary message to a group element using the suite's
    /// hash-to-group algorithm (RFC 9380).
    ///
    /// The `dst` parameter is the domain separation tag.
    fn hash_to_group(&self, msg: &[u8], dst: &[u8]) -> Vec<u8>;

    /// Maps an arbitrary message to a scalar in \[0, n-1\] using the suite's
    /// hash-to-scalar algorithm.
    ///
    /// Returns the scalar in the suite's native byte order.
    fn hash_to_scalar(&self, msg: &[u8], dst: &[u8]) -> Vec<u8>;

    /// Multiplies a serialized group element by a scalar.
    ///
    /// `element` is typically attacker-controllable (a peer's blinded element or
    /// ephemeral public key), so it is validated before the operation: a
    /// malformed encoding, an off-curve point, or the identity element returns
    /// `Err` instead of panicking. This lets a server reject a malicious request
    /// rather than aborting the handling thread (RFC 9497 §2.1).
    fn scalar_multiply(&self, scalar: &[u8], element: &[u8]) -> Result<Vec<u8>, &'static str>;

    /// Multiplies the group generator **G** by a scalar.
    fn scalar_multiply_generator(&self, scalar: &[u8]) -> Vec<u8>;

    /// Serializes a scalar to a fixed-size byte array (Ns bytes).
    ///
    /// Encoding is suite-dependent: big-endian for Weierstrass, little-endian
    /// for ristretto255.
    fn serialize_scalar(&self, scalar: &[u8]) -> Vec<u8>;

    /// Generates a uniformly random scalar in \[1, n-1\].
    fn random_scalar(&self, rng: &mut dyn rand_core::CryptoRng) -> Vec<u8>;

    /// Computes the modular inverse: scalar⁻¹ mod n.
    ///
    /// # Panics
    ///
    /// Panics if the scalar is zero (has no inverse).
    fn scalar_inverse(&self, scalar: &[u8]) -> Vec<u8>;

    /// Returns `true` if the serialized element is the group identity element.
    ///
    /// Per RFC 9497 §2.1, `DeserializeElement` must reject the identity.
    fn is_identity_element(&self, element: &[u8]) -> bool;

    // ── Verifiable-mode primitives (VOPRF / POPRF) ───────────────────────────
    //
    // Required rather than defaulted, deliberately. A default implementation
    // would let a new group compile with arithmetic that silently ignores its
    // own encoding conventions; a missing one is a compile error.

    /// Returns the group generator **G**, serialized.
    fn generator(&self) -> Vec<u8>;

    /// Returns `Ok` only for a valid, canonical, non-identity element encoding.
    ///
    /// Identity handling is asymmetric across the supported groups: the NIST
    /// identity has no compressed SEC1 encoding and decoding rejects it anyway,
    /// while the ristretto255 identity is the all-zero encoding and decompresses
    /// happily. Both are rejected here so the guarantee is uniform.
    fn validate_element(&self, element: &[u8]) -> Result<(), &'static str>;

    /// Parses a scalar from its canonical encoding, rejecting a non-canonical one.
    ///
    /// The range check is what makes a DLEQ proof non-malleable: without it, `c`
    /// and `c + n` are distinct byte strings that verify identically. Every
    /// positive test vector passes either way, so this needs its own negative
    /// test.
    ///
    /// Distinct from [`Self::serialize_scalar`]'s inverse in one respect: that
    /// method pads and truncates, where this one refuses.
    fn deserialize_scalar(&self, bytes: &[u8]) -> Result<Vec<u8>, &'static str>;

    /// Computes the multi-scalar multiplication Σ `scalars[i] * elements[i]`.
    ///
    /// One operation rather than a composition of multiply-then-add: the
    /// composed form has to serialize an intermediate that may be the identity,
    /// which has no encoding on the NIST curves, and so would report a zero
    /// scalar as a malformed element rather than as the identity result
    /// RFC 9497 asks the caller to detect.
    ///
    /// Returns `Err` if the sum is the identity.
    fn linear_combination(
        &self,
        scalars: &[&[u8]],
        elements: &[&[u8]],
    ) -> Result<Vec<u8>, &'static str>;

    /// Adds two scalars mod *n*, returning the suite's canonical encoding.
    fn scalar_add(&self, a: &[u8], b: &[u8]) -> Vec<u8>;

    /// Subtracts two scalars mod *n*, returning the suite's canonical encoding.
    ///
    /// The reduction is not optional: `r - c*k` is negative for the common case
    /// in `GenerateProof`, and a signed intermediate does not encode.
    fn scalar_sub(&self, a: &[u8], b: &[u8]) -> Vec<u8>;

    /// Multiplies two scalars mod *n*, returning the suite's canonical encoding.
    fn scalar_mul(&self, a: &[u8], b: &[u8]) -> Vec<u8>;

    /// Returns `true` if the scalar is congruent to zero mod *n*.
    fn scalar_is_zero(&self, scalar: &[u8]) -> bool;
}
