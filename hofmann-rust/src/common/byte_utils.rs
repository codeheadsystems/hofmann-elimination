/// Integer to Octet String Primitive (I2OSP) from RFC 8017.
///
/// Converts a non-negative integer to a big-endian byte array of the specified
/// length. Used extensively in RFC 9380 and RFC 9497 for length-prefixing.
///
/// # Examples
///
/// ```
/// use hofmann_rfc::common::i2osp;
///
/// assert_eq!(i2osp(256, 2), vec![1, 0]);
/// assert_eq!(i2osp(0, 1), vec![0]);
/// ```
pub fn i2osp(value: u32, length: usize) -> Vec<u8> {
    let mut result = vec![0u8; length];
    let mut v = value;
    for i in (0..length).rev() {
        result[i] = (v & 0xFF) as u8;
        v >>= 8;
    }
    result
}

/// Concatenates multiple byte slices into a single `Vec<u8>`.
///
/// # Examples
///
/// ```
/// use hofmann_rfc::common::concat;
///
/// assert_eq!(concat(&[&[1, 2], &[3, 4]]), vec![1, 2, 3, 4]);
/// ```
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let total: usize = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total);
    for s in slices {
        result.extend_from_slice(s);
    }
    result
}

/// XOR two byte slices of equal length.
///
/// # Panics
///
/// Panics if the slices have different lengths.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "XOR arrays must have equal length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Constant-time byte slice comparison using the `subtle` crate.
///
/// Returns `true` if and only if both slices have equal length and identical
/// contents. The comparison runs in constant time to prevent timing
/// side-channel attacks on MAC verification.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i2osp() {
        assert_eq!(i2osp(0, 1), vec![0]);
        assert_eq!(i2osp(1, 1), vec![1]);
        assert_eq!(i2osp(256, 2), vec![1, 0]);
        assert_eq!(i2osp(0, 2), vec![0, 0]);
    }

    #[test]
    fn test_concat() {
        assert_eq!(concat(&[&[1, 2], &[3, 4]]), vec![1, 2, 3, 4]);
        assert_eq!(concat(&[&[], &[1]]), vec![1]);
    }

    #[test]
    fn test_xor() {
        assert_eq!(xor(&[0xFF, 0x00], &[0x0F, 0xF0]), vec![0xF0, 0xF0]);
    }
}
