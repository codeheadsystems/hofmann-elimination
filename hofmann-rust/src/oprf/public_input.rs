//! RFC 9497 §3.3.3 public input handling for POPRF.

use crate::common::{concat, i2osp};
use crate::oprf::cipher_suite::OprfCipherSuite;

/// The largest public input the transcript can express.
///
/// `I2OSP(len(info), 2)` bounds it at 65535, and this stops one short so the
/// bound is obviously safe rather than exactly at the limit.
pub const MAX_LENGTH: usize = 65534;

/// Rejects a public input the transcript cannot encode.
pub fn validate(info: &[u8]) -> Result<(), &'static str> {
    if info.len() > MAX_LENGTH {
        return Err("public input exceeds the maximum encodable length");
    }
    Ok(())
}

/// Derives the key tweak `m = HashToScalar("Info" || I2OSP(len(info), 2) || info)`.
///
/// The framing matters: the label, then a two-byte length, then the input. It is
/// hashed to a scalar with the suite's ordinary `HashToScalar-` DST, not with any
/// proof-specific or POPRF-specific tag — mode separation is already carried by
/// the context string inside that DST.
pub fn to_scalar(suite: &OprfCipherSuite, info: &[u8]) -> Result<Vec<u8>, &'static str> {
    validate(info)?;
    let framed = concat(&[b"Info", &i2osp(info.len() as u32, 2), info]);
    Ok(suite
        .group_spec()
        .hash_to_scalar(&framed, suite.hash_to_scalar_dst()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oprf::{CurveHashSuite, OprfMode};

    fn suite() -> OprfCipherSuite {
        OprfCipherSuite::new_with_mode(CurveHashSuite::P256Sha256, OprfMode::Poprf)
    }

    #[test]
    fn empty_info_is_a_real_public_input() {
        // Not the absence of one: it hashes to a definite scalar, and to a
        // different scalar than any non-empty input.
        let empty = to_scalar(&suite(), b"").unwrap();
        let non_empty = to_scalar(&suite(), b"tenant-a").unwrap();

        assert_eq!(empty.len(), 32);
        assert_ne!(empty, non_empty);
    }

    #[test]
    fn is_deterministic() {
        assert_eq!(
            to_scalar(&suite(), b"tenant-a").unwrap(),
            to_scalar(&suite(), b"tenant-a").unwrap()
        );
    }

    /// The length prefix is what stops `"ab" || "c"` colliding with `"a" || "bc"`.
    #[test]
    fn length_prefix_separates_inputs_that_would_otherwise_concatenate_alike() {
        assert_ne!(
            to_scalar(&suite(), b"abc").unwrap(),
            to_scalar(&suite(), b"ab").unwrap()
        );
    }

    #[test]
    fn over_length_info_is_rejected() {
        assert!(validate(&vec![0u8; MAX_LENGTH + 1]).is_err());
        assert!(validate(&vec![0u8; MAX_LENGTH]).is_ok());
    }
}
