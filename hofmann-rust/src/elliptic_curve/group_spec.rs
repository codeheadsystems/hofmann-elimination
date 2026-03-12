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
    /// Performs point validation before the operation.
    fn scalar_multiply(&self, scalar: &[u8], element: &[u8]) -> Vec<u8>;

    /// Multiplies the group generator **G** by a scalar.
    fn scalar_multiply_generator(&self, scalar: &[u8]) -> Vec<u8>;

    /// Serializes a scalar to a fixed-size byte array (Ns bytes).
    ///
    /// Encoding is suite-dependent: big-endian for Weierstrass, little-endian
    /// for ristretto255.
    fn serialize_scalar(&self, scalar: &[u8]) -> Vec<u8>;

    /// Generates a uniformly random scalar in \[1, n-1\].
    fn random_scalar(&self, rng: &mut dyn rand_core::CryptoRngCore) -> Vec<u8>;

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
}
