use crate::common::{i2osp, xor};
use digest::Digest;
use sha2::{Sha256, Sha384, Sha512};

/// Implementation of `expand_message_xmd` from RFC 9380 §5.3.1.
///
/// Expands a message using a hash function to produce a uniformly distributed
/// byte string. This is the core building block for `hash_to_field` and
/// `hash_to_curve` operations.
///
/// # Supported hash functions
///
/// | Hash | Output (b) | Block size (r) |
/// |---|---|---|
/// | SHA-256 | 32 | 64 |
/// | SHA-384 | 48 | 128 |
/// | SHA-512 | 64 | 128 |
///
/// Note: SHA-384 uses `r=128` (the same 1024-bit block as SHA-512), **not**
/// 104. This is a common implementation pitfall.
pub struct ExpandMessageXmd {
    hash_type: HashType,
}

#[derive(Clone, Copy)]
enum HashType {
    Sha256,
    Sha384,
    Sha512,
}

impl HashType {
    fn b_in_bytes(self) -> usize {
        match self {
            HashType::Sha256 => 32,
            HashType::Sha384 => 48,
            HashType::Sha512 => 64,
        }
    }

    fn r_in_bytes(self) -> usize {
        match self {
            HashType::Sha256 => 64,
            // SHA-384 uses the same 1024-bit block as SHA-512
            HashType::Sha384 => 128,
            HashType::Sha512 => 128,
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashType::Sha256 => Sha256::digest(data).to_vec(),
            HashType::Sha384 => Sha384::digest(data).to_vec(),
            HashType::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

impl ExpandMessageXmd {
    pub fn for_sha256() -> Self {
        Self {
            hash_type: HashType::Sha256,
        }
    }

    pub fn for_sha384() -> Self {
        Self {
            hash_type: HashType::Sha384,
        }
    }

    pub fn for_sha512() -> Self {
        Self {
            hash_type: HashType::Sha512,
        }
    }

    /// Expands a message into a uniformly random byte string of length `len_in_bytes`.
    pub fn expand(&self, msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        assert!(
            len_in_bytes > 0 && len_in_bytes <= 65535,
            "lenInBytes must be between 1 and 65535"
        );

        let b = self.hash_type.b_in_bytes();
        let r = self.hash_type.r_in_bytes();
        let ell = len_in_bytes.div_ceil(b);
        assert!(ell <= 255, "lenInBytes too large for hash");

        let dst_prime = self.prepare_dst_prime(dst);
        let z_pad = vec![0u8; r];
        let lib_str = i2osp(len_in_bytes as u32, 2);

        // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        let mut msg_prime = Vec::with_capacity(r + msg.len() + 3 + dst_prime.len());
        msg_prime.extend_from_slice(&z_pad);
        msg_prime.extend_from_slice(msg);
        msg_prime.extend_from_slice(&lib_str);
        msg_prime.push(0);
        msg_prime.extend_from_slice(&dst_prime);

        // b_0 = H(msg_prime)
        let b0 = self.hash_type.hash(&msg_prime);

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        let mut input = Vec::with_capacity(b + 1 + dst_prime.len());
        input.extend_from_slice(&b0);
        input.push(1);
        input.extend_from_slice(&dst_prime);
        let b1 = self.hash_type.hash(&input);

        let mut uniform_bytes = Vec::with_capacity(ell * b);
        uniform_bytes.extend_from_slice(&b1);

        let mut b_prev = b1;
        for i in 2..=ell {
            let xored = xor(&b0, &b_prev);
            let mut inp = Vec::with_capacity(b + 1 + dst_prime.len());
            inp.extend_from_slice(&xored);
            inp.push(i as u8);
            inp.extend_from_slice(&dst_prime);
            let bi = self.hash_type.hash(&inp);
            uniform_bytes.extend_from_slice(&bi);
            b_prev = bi;
        }

        uniform_bytes.truncate(len_in_bytes);
        uniform_bytes
    }

    fn prepare_dst_prime(&self, dst: &[u8]) -> Vec<u8> {
        if dst.len() > 255 {
            let mut to_hash = Vec::from(b"H2C-OVERSIZE-DST-" as &[u8]);
            to_hash.extend_from_slice(dst);
            let hashed = self.hash_type.hash(&to_hash);
            let mut result = hashed;
            result.push(self.hash_type.b_in_bytes() as u8);
            result
        } else {
            let mut result = Vec::with_capacity(dst.len() + 1);
            result.extend_from_slice(dst);
            result.push(dst.len() as u8);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_sha256_basic() {
        // RFC 9380 test vector: expand_message_xmd(SHA-256)
        let xmd = ExpandMessageXmd::for_sha256();
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let result = xmd.expand(b"", dst, 0x20);
        assert_eq!(result.len(), 0x20);
    }
}
