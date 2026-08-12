use crate::elliptic_curve::group_spec::GroupSpec;
use elliptic_curve::consts::{U48, U72, U98};
use elliptic_curve::ops::Reduce;
use elliptic_curve::sec1::{FromSec1Point, Sec1Point, ToSec1Point};
use elliptic_curve::{AffinePoint, Curve, Field, Group, ProjectivePoint};
use hash2curve::GroupDigest;

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
                let pt = p256::NistP256::hash_from_bytes(&[msg], &[dst]).unwrap();
                let affine: AffinePoint<p256::NistP256> = pt.to_affine();
                affine.to_sec1_point(true).as_bytes().to_vec()
            }
            CurveType::P384 => {
                let pt = p384::NistP384::hash_from_bytes(&[msg], &[dst]).unwrap();
                let affine: AffinePoint<p384::NistP384> = pt.to_affine();
                affine.to_sec1_point(true).as_bytes().to_vec()
            }
            CurveType::P521 => {
                let pt = p521::NistP521::hash_from_bytes(&[msg], &[dst]).unwrap();
                let affine: AffinePoint<p521::NistP521> = pt.to_affine();
                affine.to_sec1_point(true).as_bytes().to_vec()
            }
        }
    }

    fn hash_to_scalar(&self, msg: &[u8], dst: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let scalar = hash2curve::hash_to_scalar::<
                    p256::NistP256,
                    <p256::NistP256 as GroupDigest>::ExpandMsg,
                    U48,
                >(&[msg], &[dst])
                .unwrap();
                scalar.to_bytes().to_vec()
            }
            CurveType::P384 => {
                let scalar = hash2curve::hash_to_scalar::<
                    p384::NistP384,
                    <p384::NistP384 as GroupDigest>::ExpandMsg,
                    U72,
                >(&[msg], &[dst])
                .unwrap();
                scalar.to_bytes().to_vec()
            }
            CurveType::P521 => {
                let scalar = hash2curve::hash_to_scalar::<
                    p521::NistP521,
                    <p521::NistP521 as GroupDigest>::ExpandMsg,
                    U98,
                >(&[msg], &[dst])
                .unwrap();
                scalar.to_bytes().to_vec()
            }
        }
    }

    fn scalar_multiply(&self, scalar: &[u8], element: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self.curve_type {
            CurveType::P256 => {
                let point = decode_point_p256(element)?;
                let s = decode_scalar_p256(scalar);
                let result = point * s;
                let affine: AffinePoint<p256::NistP256> = result.to_affine();
                Ok(affine.to_sec1_point(true).as_bytes().to_vec())
            }
            CurveType::P384 => {
                let point = decode_point_p384(element)?;
                let s = decode_scalar_p384(scalar);
                let result = point * s;
                let affine: AffinePoint<p384::NistP384> = result.to_affine();
                Ok(affine.to_sec1_point(true).as_bytes().to_vec())
            }
            CurveType::P521 => {
                let point = decode_point_p521(element)?;
                let s = decode_scalar_p521(scalar);
                let result = point * s;
                let affine: AffinePoint<p521::NistP521> = result.to_affine();
                Ok(affine.to_sec1_point(true).as_bytes().to_vec())
            }
        }
    }

    fn scalar_multiply_generator(&self, scalar: &[u8]) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => {
                let s = decode_scalar_p256(scalar);
                let result = ProjectivePoint::<p256::NistP256>::generator() * s;
                let affine: AffinePoint<p256::NistP256> = result.to_affine();
                affine.to_sec1_point(true).as_bytes().to_vec()
            }
            CurveType::P384 => {
                let s = decode_scalar_p384(scalar);
                let result = ProjectivePoint::<p384::NistP384>::generator() * s;
                let affine: AffinePoint<p384::NistP384> = result.to_affine();
                affine.to_sec1_point(true).as_bytes().to_vec()
            }
            CurveType::P521 => {
                let s = decode_scalar_p521(scalar);
                let result = ProjectivePoint::<p521::NistP521>::generator() * s;
                let affine: AffinePoint<p521::NistP521> = result.to_affine();
                affine.to_sec1_point(true).as_bytes().to_vec()
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

    fn random_scalar(&self, rng: &mut dyn rand_core::CryptoRng) -> Vec<u8> {
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
        element == [0x00]
            || (element.len() == self.element_size() && element.iter().all(|&b| b == 0))
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

    fn generator(&self) -> Vec<u8> {
        match self.curve_type {
            CurveType::P256 => ProjectivePoint::<p256::NistP256>::generator()
                .to_affine()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            CurveType::P384 => ProjectivePoint::<p384::NistP384>::generator()
                .to_affine()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
            CurveType::P521 => ProjectivePoint::<p521::NistP521>::generator()
                .to_affine()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec(),
        }
    }

    fn validate_element(&self, element: &[u8]) -> Result<(), &'static str> {
        // Exactly Ne bytes with a 0x02/0x03 prefix. RFC 9497 §2.1 requires
        // DeserializeElement to be the inverse of SerializeElement, and
        // accepting the uncompressed (0x04) or hybrid encodings would let a
        // re-encoding produce a proof transcript over different bytes than the
        // peer hashed.
        if element.len() != self.element_size() {
            return Err("element is not Ne bytes");
        }
        if element[0] != 0x02 && element[0] != 0x03 {
            return Err("element is not a compressed SEC1 encoding");
        }
        match self.curve_type {
            CurveType::P256 => decode_point_p256(element).map(|_| ()),
            CurveType::P384 => decode_point_p384(element).map(|_| ()),
            CurveType::P521 => decode_point_p521(element).map(|_| ()),
        }
    }

    fn deserialize_scalar(&self, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        let ns = self.scalar_size();
        if bytes.len() != ns {
            return Err("scalar is not Ns bytes");
        }
        // group_order() is the curve's own big-endian width, which is not always
        // Ns: P-521's order is a 66-byte value returned in a 72-byte U576, so
        // comparing against it unaligned would make every 66-byte scalar look
        // shorter than the order and be accepted. Right-align first.
        let order = self.group_order();
        let aligned = &order[order.len() - ns..];
        // Reducing instead of comparing would accept c and c + n as the same
        // scalar, which is exactly the malleability this check exists to prevent.
        if !lt_be(bytes, aligned) {
            return Err("scalar is not canonical (>= group order)");
        }
        Ok(bytes.to_vec())
    }

    fn linear_combination(
        &self,
        scalars: &[&[u8]],
        elements: &[&[u8]],
    ) -> Result<Vec<u8>, &'static str> {
        if scalars.len() != elements.len() || scalars.is_empty() {
            return Err("scalars and elements must be the same non-zero length");
        }
        macro_rules! combine {
            ($curve:ty, $decode_point:ident, $decode_scalar:ident) => {{
                let mut acc = ProjectivePoint::<$curve>::identity();
                for (scalar, element) in scalars.iter().zip(elements.iter()) {
                    self.validate_element(element)?;
                    let point = $decode_point(element)?;
                    acc += point * $decode_scalar(scalar);
                }
                if bool::from(acc.is_identity()) {
                    return Err("identity result rejected per RFC 9497 §2.1");
                }
                Ok(acc.to_affine().to_sec1_point(true).as_bytes().to_vec())
            }};
        }
        match self.curve_type {
            CurveType::P256 => combine!(p256::NistP256, decode_point_p256, decode_scalar_p256),
            CurveType::P384 => combine!(p384::NistP384, decode_point_p384, decode_scalar_p384),
            CurveType::P521 => combine!(p521::NistP521, decode_point_p521, decode_scalar_p521),
        }
    }

    fn scalar_add(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        dispatch_curve!(
            self,
            (decode_scalar_p256(a) + decode_scalar_p256(b))
                .to_bytes()
                .to_vec(),
            (decode_scalar_p384(a) + decode_scalar_p384(b))
                .to_bytes()
                .to_vec(),
            (decode_scalar_p521(a) + decode_scalar_p521(b))
                .to_bytes()
                .to_vec()
        )
    }

    fn scalar_sub(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        dispatch_curve!(
            self,
            (decode_scalar_p256(a) - decode_scalar_p256(b))
                .to_bytes()
                .to_vec(),
            (decode_scalar_p384(a) - decode_scalar_p384(b))
                .to_bytes()
                .to_vec(),
            (decode_scalar_p521(a) - decode_scalar_p521(b))
                .to_bytes()
                .to_vec()
        )
    }

    fn scalar_mul(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        dispatch_curve!(
            self,
            (decode_scalar_p256(a) * decode_scalar_p256(b))
                .to_bytes()
                .to_vec(),
            (decode_scalar_p384(a) * decode_scalar_p384(b))
                .to_bytes()
                .to_vec(),
            (decode_scalar_p521(a) * decode_scalar_p521(b))
                .to_bytes()
                .to_vec()
        )
    }

    fn scalar_is_zero(&self, scalar: &[u8]) -> bool {
        dispatch_curve!(
            self,
            bool::from(decode_scalar_p256(scalar).is_zero()),
            bool::from(decode_scalar_p384(scalar).is_zero()),
            bool::from(decode_scalar_p521(scalar).is_zero())
        )
    }
}

/// Big-endian `a < b` for equal-length byte strings, without early exit.
///
/// Constant time is not load-bearing here — both operands are public — but a
/// branchless comparison is no harder to write than a branching one.
fn lt_be(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return a.len() < b.len();
    }
    let mut lt: u8 = 0;
    let mut gt: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        let decided = lt | gt;
        let mask = (decided == 0) as u8;
        lt |= mask & ((x < y) as u8);
        gt |= mask & ((x > y) as u8);
    }
    lt == 1
}

// --- P-256 helpers ---

/// Decodes big-endian bytes into a P-256 scalar via modular reduction.
fn decode_scalar_p256(bytes: &[u8]) -> p256::Scalar {
    use elliptic_curve::bigint::U256;
    let uint = U256::from_be_slice(bytes);
    <p256::Scalar as Reduce<U256>>::reduce(&uint)
}

/// Decodes a compressed SEC1 P-256 point into projective coordinates.
///
/// Returns `Err` (rather than panicking) on any attacker-controllable failure:
/// a malformed encoding, an off-curve point, or the identity element
/// (rejected per RFC 9497 §2.1).
fn decode_point_p256(bytes: &[u8]) -> Result<ProjectivePoint<p256::NistP256>, &'static str> {
    let encoded = Sec1Point::<p256::NistP256>::from_bytes(bytes)
        .map_err(|_| "invalid P-256 point encoding")?;
    let affine = AffinePoint::<p256::NistP256>::from_sec1_point(&encoded);
    if bool::from(affine.is_none()) {
        return Err("P-256 point is not on the curve");
    }
    let pt: ProjectivePoint<p256::NistP256> = affine.unwrap().into();
    if bool::from(pt.is_identity()) {
        return Err("identity element rejected per RFC 9497 §2.1");
    }
    Ok(pt)
}

// --- P-384 helpers ---

/// Decodes big-endian bytes into a P-384 scalar via modular reduction.
fn decode_scalar_p384(bytes: &[u8]) -> p384::Scalar {
    use elliptic_curve::bigint::U384;
    let uint = U384::from_be_slice(bytes);
    <p384::Scalar as Reduce<U384>>::reduce(&uint)
}

/// Decodes a compressed SEC1 P-384 point into projective coordinates.
///
/// Returns `Err` (rather than panicking) on any attacker-controllable failure:
/// a malformed encoding, an off-curve point, or the identity element
/// (rejected per RFC 9497 §2.1).
fn decode_point_p384(bytes: &[u8]) -> Result<ProjectivePoint<p384::NistP384>, &'static str> {
    let encoded = Sec1Point::<p384::NistP384>::from_bytes(bytes)
        .map_err(|_| "invalid P-384 point encoding")?;
    let affine = AffinePoint::<p384::NistP384>::from_sec1_point(&encoded);
    if bool::from(affine.is_none()) {
        return Err("P-384 point is not on the curve");
    }
    let pt: ProjectivePoint<p384::NistP384> = affine.unwrap().into();
    if bool::from(pt.is_identity()) {
        return Err("identity element rejected per RFC 9497 §2.1");
    }
    Ok(pt)
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
    <p521::Scalar as Reduce<U576>>::reduce(&uint)
}

/// Decodes a compressed SEC1 P-521 point into projective coordinates.
///
/// Returns `Err` (rather than panicking) on any attacker-controllable failure:
/// a malformed encoding, an off-curve point, or the identity element
/// (rejected per RFC 9497 §2.1).
fn decode_point_p521(bytes: &[u8]) -> Result<ProjectivePoint<p521::NistP521>, &'static str> {
    let encoded = Sec1Point::<p521::NistP521>::from_bytes(bytes)
        .map_err(|_| "invalid P-521 point encoding")?;
    let affine = AffinePoint::<p521::NistP521>::from_sec1_point(&encoded);
    if bool::from(affine.is_none()) {
        return Err("P-521 point is not on the curve");
    }
    let pt: ProjectivePoint<p521::NistP521> = affine.unwrap().into();
    if bool::from(pt.is_identity()) {
        return Err("identity element rejected per RFC 9497 §2.1");
    }
    Ok(pt)
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
        let mut rng = rand::rng();
        let scalar = gs.random_scalar(&mut rng);
        let inv = gs.scalar_inverse(&scalar);
        // scalar * inv should give 1 when multiplied as scalars
        let s = decode_scalar_p256(&scalar);
        let i = decode_scalar_p256(&inv);
        let product = s * i;
        assert_eq!(product, p256::Scalar::ONE);
    }
}
