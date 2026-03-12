use crate::elliptic_curve::group_spec::GroupSpec;
use elliptic_curve::bigint::Encoding as _;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::ops::Reduce;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{AffinePoint, Curve, Field, Group, ProjectivePoint};

/// Supported NIST Weierstrass curve types.
///
/// Each variant maps to its corresponding RustCrypto crate (`p256`, `p384`,
/// `p521`) and determines the hash function used for hash-to-curve
/// (SHA-256, SHA-384, SHA-512 respectively).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    /// NIST P-256 (secp256r1). Element size: 33 bytes, scalar size: 32 bytes.
    P256,
    /// NIST P-384 (secp384r1). Element size: 49 bytes, scalar size: 48 bytes.
    P384,
    /// NIST P-521 (secp521r1). Element size: 67 bytes, scalar size: 66 bytes.
    P521,
}

/// [`GroupSpec`] implementation for NIST Weierstrass curves (P-256, P-384, P-521).
///
/// Uses the RustCrypto ecosystem (`p256`, `p384`, `p521` crates) for all
/// arithmetic. Group elements are encoded as **compressed SEC1** points
/// (0x02/0x03 prefix + x-coordinate). Scalars are **big-endian**.
///
/// A `dispatch_curve!` macro handles runtime dispatch across the three curves,
/// since each RustCrypto curve is a separate generic type.
pub struct WeierstrassGroupSpec {
    curve_type: CurveType,
}

impl WeierstrassGroupSpec {
    pub fn new(curve_type: CurveType) -> Self {
        Self { curve_type }
    }

    pub fn p256() -> Self {
        Self::new(CurveType::P256)
    }
    pub fn p384() -> Self {
        Self::new(CurveType::P384)
    }
    pub fn p521() -> Self {
        Self::new(CurveType::P521)
    }
}

// Macro to avoid repeating the same logic for each curve.
// The RustCrypto crates use generics, so we dispatch at runtime.
macro_rules! dispatch_curve {
    ($self:expr, $p256_block:expr, $p384_block:expr, $p521_block:expr) => {
        match $self.curve_type {
            CurveType::P256 => $p256_block,
            CurveType::P384 => $p384_block,
            CurveType::P521 => $p521_block,
        }
    };
}

impl GroupSpec for WeierstrassGroupSpec {
    fn group_order(&self) -> Vec<u8> {
        dispatch_curve!(
            self,
            p256::NistP256::ORDER.to_be_bytes().to_vec(),
            p384::NistP384::ORDER.to_be_bytes().to_vec(),
            p521::NistP521::ORDER.to_be_bytes().to_vec()
        )
    }

    fn element_size(&self) -> usize {
        dispatch_curve!(self, 33, 49, 67)
    }

    fn scalar_size(&self) -> usize {
        dispatch_curve!(self, 32, 48, 66)
    }

    fn hash_to_group(&self, msg: &[u8], dst: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let pt =
                    p256::NistP256::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(&[msg], &[dst])
                        .unwrap();
                let affine: AffinePoint<p256::NistP256> = pt.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
            CurveType::P384 => {
                let pt =
                    p384::NistP384::hash_from_bytes::<ExpandMsgXmd<sha2::Sha384>>(&[msg], &[dst])
                        .unwrap();
                let affine: AffinePoint<p384::NistP384> = pt.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
            CurveType::P521 => {
                let pt =
                    p521::NistP521::hash_from_bytes::<ExpandMsgXmd<sha2::Sha512>>(&[msg], &[dst])
                        .unwrap();
                let affine: AffinePoint<p521::NistP521> = pt.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
        }
    }

    fn hash_to_scalar(&self, msg: &[u8], dst: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let scalar =
                    p256::NistP256::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&[msg], &[dst])
                        .unwrap();
                scalar.to_bytes().to_vec()
            }
            CurveType::P384 => {
                let scalar =
                    p384::NistP384::hash_to_scalar::<ExpandMsgXmd<sha2::Sha384>>(&[msg], &[dst])
                        .unwrap();
                scalar.to_bytes().to_vec()
            }
            CurveType::P521 => {
                let scalar =
                    p521::NistP521::hash_to_scalar::<ExpandMsgXmd<sha2::Sha512>>(&[msg], &[dst])
                        .unwrap();
                scalar.to_bytes().to_vec()
            }
        }
    }

    fn scalar_multiply(&self, scalar: &[u8], element: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let point = decode_point_p256(element);
                let s = decode_scalar_p256(scalar);
                let result = point * s;
                let affine: AffinePoint<p256::NistP256> = result.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
            CurveType::P384 => {
                let point = decode_point_p384(element);
                let s = decode_scalar_p384(scalar);
                let result = point * s;
                let affine: AffinePoint<p384::NistP384> = result.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
            CurveType::P521 => {
                let point = decode_point_p521(element);
                let s = decode_scalar_p521(scalar);
                let result = point * s;
                let affine: AffinePoint<p521::NistP521> = result.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
        }
    }

    fn scalar_multiply_generator(&self, scalar: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let s = decode_scalar_p256(scalar);
                let result = ProjectivePoint::<p256::NistP256>::generator() * s;
                let affine: AffinePoint<p256::NistP256> = result.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
            CurveType::P384 => {
                let s = decode_scalar_p384(scalar);
                let result = ProjectivePoint::<p384::NistP384>::generator() * s;
                let affine: AffinePoint<p384::NistP384> = result.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
            CurveType::P521 => {
                let s = decode_scalar_p521(scalar);
                let result = ProjectivePoint::<p521::NistP521>::generator() * s;
                let affine: AffinePoint<p521::NistP521> = result.to_affine();
                affine.to_encoded_point(true).as_bytes().to_vec()
            }
        }
    }

    fn serialize_scalar(&self, scalar: &[u8]) -> Vec<u8> {
        // Big-endian, pad to scalar_size
        let size = self.scalar_size();
        let mut result = vec![0u8; size];
        let start = size.saturating_sub(scalar.len());
        let src_start = scalar.len().saturating_sub(size);
        result[start..].copy_from_slice(&scalar[src_start..]);
        result
    }

    fn random_scalar(&self, rng: &mut dyn rand_core::CryptoRngCore) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let scalar = <p256::Scalar as Field>::random(rng);
                scalar.to_bytes().to_vec()
            }
            CurveType::P384 => {
                let scalar = <p384::Scalar as Field>::random(rng);
                scalar.to_bytes().to_vec()
            }
            CurveType::P521 => {
                let scalar = <p521::Scalar as Field>::random(rng);
                scalar.to_bytes().to_vec()
            }
        }
    }

    fn is_identity_element(&self, element: &[u8]) -> bool {
        // SEC1 identity is a single 0x00 byte; also reject all-zero encodings
        // of the expected element size as a defense-in-depth measure.
        element == [0x00] || (element.len() == self.element_size() && element.iter().all(|&b| b == 0))
    }

    fn scalar_inverse(&self, scalar: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let s = decode_scalar_p256(scalar);
                let inv = s.invert();
                if bool::from(inv.is_none()) {
                    panic!("scalar has no inverse");
                }
                inv.unwrap().to_bytes().to_vec()
            }
            CurveType::P384 => {
                let s = decode_scalar_p384(scalar);
                let inv = s.invert();
                if bool::from(inv.is_none()) {
                    panic!("scalar has no inverse");
                }
                inv.unwrap().to_bytes().to_vec()
            }
            CurveType::P521 => {
                let s = decode_scalar_p521(scalar);
                let inv = s.invert();
                if bool::from(inv.is_none()) {
                    panic!("scalar has no inverse");
                }
                inv.unwrap().to_bytes().to_vec()
            }
        }
    }
}

// --- P-256 helpers ---

/// Decodes big-endian bytes into a P-256 scalar via modular reduction.
fn decode_scalar_p256(bytes: &[u8]) -> p256::Scalar {
    use elliptic_curve::bigint::U256;
    let uint = U256::from_be_slice(bytes);
    <p256::Scalar as Reduce<U256>>::reduce(uint)
}

/// Decodes a compressed SEC1 P-256 point into projective coordinates.
///
/// Rejects the identity element per RFC 9497 §2.1.
fn decode_point_p256(bytes: &[u8]) -> ProjectivePoint<p256::NistP256> {
    let encoded = p256::EncodedPoint::from_bytes(bytes).expect("invalid P-256 encoded point");
    let affine = AffinePoint::<p256::NistP256>::from_encoded_point(&encoded);
    if bool::from(affine.is_none()) {
        panic!("invalid P-256 point");
    }
    let pt: ProjectivePoint<p256::NistP256> = affine.unwrap().into();
    assert!(
        !bool::from(pt.is_identity()),
        "identity element rejected per RFC 9497 §2.1"
    );
    pt
}

// --- P-384 helpers ---

/// Decodes big-endian bytes into a P-384 scalar via modular reduction.
fn decode_scalar_p384(bytes: &[u8]) -> p384::Scalar {
    use elliptic_curve::bigint::U384;
    let uint = U384::from_be_slice(bytes);
    <p384::Scalar as Reduce<U384>>::reduce(uint)
}

/// Decodes a compressed SEC1 P-384 point into projective coordinates.
///
/// Rejects the identity element per RFC 9497 §2.1.
fn decode_point_p384(bytes: &[u8]) -> ProjectivePoint<p384::NistP384> {
    let encoded = p384::EncodedPoint::from_bytes(bytes).expect("invalid P-384 encoded point");
    let affine = AffinePoint::<p384::NistP384>::from_encoded_point(&encoded);
    if bool::from(affine.is_none()) {
        panic!("invalid P-384 point");
    }
    let pt: ProjectivePoint<p384::NistP384> = affine.unwrap().into();
    assert!(
        !bool::from(pt.is_identity()),
        "identity element rejected per RFC 9497 §2.1"
    );
    pt
}

// --- P-521 helpers ---

/// Decodes big-endian bytes into a P-521 scalar via modular reduction.
///
/// P-521 scalars are 66 bytes but `U576` requires 72 bytes, so we zero-pad
/// to the left before calling `from_be_slice`.
///
/// # Panics
///
/// Panics if `bytes` is longer than 72 bytes.
fn decode_scalar_p521(bytes: &[u8]) -> p521::Scalar {
    use elliptic_curve::bigint::U576;
    assert!(
        bytes.len() <= 72,
        "P-521 scalar bytes too long: {} > 72",
        bytes.len()
    );
    let mut padded = [0u8; 72];
    let start = 72 - bytes.len();
    padded[start..].copy_from_slice(bytes);
    let uint = U576::from_be_slice(&padded);
    <p521::Scalar as Reduce<U576>>::reduce(uint)
}

/// Decodes a compressed SEC1 P-521 point into projective coordinates.
///
/// Rejects the identity element per RFC 9497 §2.1.
fn decode_point_p521(bytes: &[u8]) -> ProjectivePoint<p521::NistP521> {
    let encoded = p521::EncodedPoint::from_bytes(bytes).expect("invalid P-521 encoded point");
    let affine = AffinePoint::<p521::NistP521>::from_encoded_point(&encoded);
    if bool::from(affine.is_none()) {
        panic!("invalid P-521 point");
    }
    let pt: ProjectivePoint<p521::NistP521> = affine.unwrap().into();
    assert!(
        !bool::from(pt.is_identity()),
        "identity element rejected per RFC 9497 §2.1"
    );
    pt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_generator_multiply() {
        let gs = WeierstrassGroupSpec::p256();
        let scalar = vec![0u8; 31]
            .into_iter()
            .chain(std::iter::once(1u8))
            .collect::<Vec<_>>();
        let result = gs.scalar_multiply_generator(&scalar);
        // Generator * 1 should give the generator point
        assert_eq!(result.len(), 33); // compressed P-256 point
        assert!(result[0] == 0x02 || result[0] == 0x03);
    }

    #[test]
    fn test_p384_generator_multiply() {
        let gs = WeierstrassGroupSpec::p384();
        let scalar = vec![0u8; 47]
            .into_iter()
            .chain(std::iter::once(1u8))
            .collect::<Vec<_>>();
        let result = gs.scalar_multiply_generator(&scalar);
        assert_eq!(result.len(), 49);
    }

    #[test]
    fn test_p521_generator_multiply() {
        let gs = WeierstrassGroupSpec::p521();
        let scalar = vec![0u8; 65]
            .into_iter()
            .chain(std::iter::once(1u8))
            .collect::<Vec<_>>();
        let result = gs.scalar_multiply_generator(&scalar);
        assert_eq!(result.len(), 67);
    }

    #[test]
    fn test_scalar_inverse_p256() {
        let gs = WeierstrassGroupSpec::p256();
        let mut rng = rand::thread_rng();
        let scalar = gs.random_scalar(&mut rng);
        let inv = gs.scalar_inverse(&scalar);
        // scalar * inv should give 1 when multiplied as scalars
        let s = decode_scalar_p256(&scalar);
        let i = decode_scalar_p256(&inv);
        let product = s * i;
        assert_eq!(product, p256::Scalar::ONE);
    }
}
