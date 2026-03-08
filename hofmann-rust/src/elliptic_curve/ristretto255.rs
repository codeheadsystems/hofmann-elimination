use crate::elliptic_curve::expand_message_xmd::ExpandMessageXmd;
use crate::elliptic_curve::group_spec::GroupSpec;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// GroupSpec implementation for ristretto255 (RFC 9496).
///
/// Uses `curve25519-dalek` for all group operations.
/// - Elements: 32-byte canonical ristretto255 encoding
/// - Scalars: 32-byte little-endian encoding
/// - hash_to_group: expand_message_xmd(SHA-512) to 64 bytes, then `from_uniform_bytes`
/// - hash_to_scalar: expand_message_xmd(SHA-512) to 64 bytes, then `from_bytes_mod_order_wide`
pub struct Ristretto255GroupSpec;

/// Group order L = 2^252 + 27742317777372353535851937790883648493
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10,
];

impl Ristretto255GroupSpec {
    fn xmd() -> ExpandMessageXmd {
        ExpandMessageXmd::for_sha512()
    }

    /// Returns the group order L as big-endian bytes (for compatibility with the trait).
    fn group_order_be() -> Vec<u8> {
        let mut be = GROUP_ORDER_LE;
        be.reverse();
        be.to_vec()
    }
}

impl GroupSpec for Ristretto255GroupSpec {
    fn group_order(&self) -> Vec<u8> {
        Ristretto255GroupSpec::group_order_be()
    }

    fn element_size(&self) -> usize {
        32
    }

    fn scalar_size(&self) -> usize {
        32
    }

    /// hash_to_ristretto255 per RFC 9496 §4.3.4.
    ///
    /// Expands message to 64 bytes via expand_message_xmd(SHA-512),
    /// then uses `RistrettoPoint::from_uniform_bytes` which implements the
    /// ristretto255 map internally (two Elligator maps + addition).
    fn hash_to_group(&self, msg: &[u8], dst: &[u8]) -> Vec<u8> {
        let uniform = Self::xmd().expand(msg, dst, 64);
        let uniform_arr: [u8; 64] = uniform.try_into().expect("expand returned wrong length");
        let point = RistrettoPoint::from_uniform_bytes(&uniform_arr);
        point.compress().to_bytes().to_vec()
    }

    /// HashToScalar per RFC 9497 §4.4: expand to 64 bytes, decode as little-endian mod L.
    ///
    /// Returns scalar in **little-endian** format (ristretto255 convention).
    fn hash_to_scalar(&self, msg: &[u8], dst: &[u8]) -> Vec<u8> {
        let uniform = Self::xmd().expand(msg, dst, 64);
        let uniform_arr: [u8; 64] = uniform.try_into().expect("expand returned wrong length");
        let scalar = Scalar::from_bytes_mod_order_wide(&uniform_arr);
        scalar.to_bytes().to_vec()
    }

    fn scalar_multiply(&self, scalar: &[u8], element: &[u8]) -> Vec<u8> {
        let point = decompress_point(element);
        let s = decode_scalar(scalar);
        let result = s * point;
        result.compress().to_bytes().to_vec()
    }

    fn scalar_multiply_generator(&self, scalar: &[u8]) -> Vec<u8> {
        let s = decode_scalar(scalar);
        let result = s * RISTRETTO_BASEPOINT_POINT;
        result.compress().to_bytes().to_vec()
    }

    /// Serializes scalar as 32-byte little-endian (ristretto255 convention).
    fn serialize_scalar(&self, scalar: &[u8]) -> Vec<u8> {
        // Already LE for ristretto255; just ensure 32 bytes
        let mut result = vec![0u8; 32];
        let copy_len = scalar.len().min(32);
        result[..copy_len].copy_from_slice(&scalar[..copy_len]);
        result
    }

    fn random_scalar(&self, rng: &mut dyn rand_core::CryptoRngCore) -> Vec<u8> {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&scalar_bytes);
        scalar.to_bytes().to_vec()
    }

    fn scalar_inverse(&self, scalar: &[u8]) -> Vec<u8> {
        let s = decode_scalar(scalar);
        let inv = s.invert();
        inv.to_bytes().to_vec()
    }
}

/// Decodes little-endian bytes into a ristretto255 scalar via modular reduction.
fn decode_scalar(bytes: &[u8]) -> Scalar {
    let mut arr = [0u8; 32];
    let copy_len = bytes.len().min(32);
    arr[..copy_len].copy_from_slice(&bytes[..copy_len]);
    // Use from_bytes_mod_order to handle any 32-byte input
    Scalar::from_bytes_mod_order(arr)
}

/// Decompresses a 32-byte canonical ristretto255 encoding into a group element.
fn decompress_point(bytes: &[u8]) -> RistrettoPoint {
    let compressed = CompressedRistretto::from_slice(bytes)
        .expect("invalid ristretto255 encoding length");
    compressed
        .decompress()
        .expect("invalid ristretto255 point encoding")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_multiply_identity() {
        let gs = Ristretto255GroupSpec;
        // scalar = 1 in LE
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let result = gs.scalar_multiply_generator(&scalar);
        assert_eq!(result.len(), 32);

        // Verify it matches the basepoint encoding
        let expected = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        assert_eq!(result, expected.to_vec());
    }

    #[test]
    fn test_scalar_inverse_roundtrip() {
        let gs = Ristretto255GroupSpec;
        let mut rng = rand::thread_rng();
        let scalar = gs.random_scalar(&mut rng);
        let inv = gs.scalar_inverse(&scalar);

        // scalar * inv should give identity scalar (1)
        let s = decode_scalar(&scalar);
        let i = decode_scalar(&inv);
        let product = s * i;
        assert_eq!(product, Scalar::ONE);
    }

    #[test]
    fn test_hash_to_group_deterministic() {
        let gs = Ristretto255GroupSpec;
        let dst = b"OPRFV1-\x00-ristretto255-SHA512";
        let msg = b"test message";

        let result1 = gs.hash_to_group(msg, dst);
        let result2 = gs.hash_to_group(msg, dst);
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_hash_to_scalar_deterministic() {
        let gs = Ristretto255GroupSpec;
        let dst = b"HashToScalar-OPRFV1-\x00-ristretto255-SHA512";
        let msg = b"test input";

        let result1 = gs.hash_to_scalar(msg, dst);
        let result2 = gs.hash_to_scalar(msg, dst);
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_scalar_multiply_roundtrip() {
        let gs = Ristretto255GroupSpec;
        let mut rng = rand::thread_rng();

        let scalar = gs.random_scalar(&mut rng);
        let point = gs.scalar_multiply_generator(&scalar);

        // Multiply by inverse should give back the generator
        let inv = gs.scalar_inverse(&scalar);
        let recovered = gs.scalar_multiply(&inv, &point);

        let expected = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        assert_eq!(recovered, expected.to_vec());
    }

    #[test]
    fn test_element_size() {
        let gs = Ristretto255GroupSpec;
        assert_eq!(gs.element_size(), 32);
        assert_eq!(gs.scalar_size(), 32);
    }
}
