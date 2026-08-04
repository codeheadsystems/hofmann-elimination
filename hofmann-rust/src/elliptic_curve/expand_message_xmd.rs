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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── RFC 9380 Appendix K.1: expand_message_xmd(SHA-256), standard DST ──

    const DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

    #[test]
    fn rfc9380_k1_empty_msg_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let result = xmd.expand(b"", DST, 0x20);
        assert_eq!(
            result,
            hex("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
        );
    }

    #[test]
    fn rfc9380_k1_abc_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let result = xmd.expand(b"abc", DST, 0x20);
        assert_eq!(
            result,
            hex("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
        );
    }

    #[test]
    fn rfc9380_k1_abcdef0123456789_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let result = xmd.expand(b"abcdef0123456789", DST, 0x20);
        assert_eq!(
            result,
            hex("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1")
        );
    }

    #[test]
    fn rfc9380_k1_q128_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let msg = "q128_".to_string() + &"q".repeat(128);
        let result = xmd.expand(msg.as_bytes(), DST, 0x20);
        assert_eq!(
            result,
            hex("b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9")
        );
    }

    #[test]
    fn rfc9380_k1_a512_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let msg = "a512_".to_string() + &"a".repeat(512);
        let result = xmd.expand(msg.as_bytes(), DST, 0x20);
        assert_eq!(
            result,
            hex("4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c")
        );
    }

    #[test]
    fn rfc9380_k1_empty_msg_len128() {
        let xmd = ExpandMessageXmd::for_sha256();
        let result = xmd.expand(b"", DST, 0x80);
        assert_eq!(
            result,
            hex("af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced")
        );
    }

    #[test]
    fn rfc9380_k1_abc_len128() {
        let xmd = ExpandMessageXmd::for_sha256();
        let result = xmd.expand(b"abc", DST, 0x80);
        assert_eq!(
            result,
            hex("abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40")
        );
    }

    // ── RFC 9380 Appendix K.2: expand_message_xmd(SHA-256), long DST (256 bytes) ──

    fn long_dst() -> Vec<u8> {
        let mut dst = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-".to_vec();
        dst.extend(std::iter::repeat_n(b'1', 208));
        assert_eq!(dst.len(), 256);
        dst
    }

    #[test]
    fn rfc9380_k2_empty_msg_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let dst = long_dst();
        let result = xmd.expand(b"", &dst, 0x20);
        assert_eq!(
            result,
            hex("e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3")
        );
    }

    #[test]
    fn rfc9380_k2_abc_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let dst = long_dst();
        let result = xmd.expand(b"abc", &dst, 0x20);
        assert_eq!(
            result,
            hex("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12")
        );
    }

    #[test]
    fn rfc9380_k2_abcdef0123456789_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let dst = long_dst();
        let result = xmd.expand(b"abcdef0123456789", &dst, 0x20);
        assert_eq!(
            result,
            hex("35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521")
        );
    }

    #[test]
    fn rfc9380_k2_q128_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let dst = long_dst();
        let msg = "q128_".to_string() + &"q".repeat(128);
        let result = xmd.expand(msg.as_bytes(), &dst, 0x20);
        assert_eq!(
            result,
            hex("01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc")
        );
    }

    #[test]
    fn rfc9380_k2_a512_len32() {
        let xmd = ExpandMessageXmd::for_sha256();
        let dst = long_dst();
        let msg = "a512_".to_string() + &"a".repeat(512);
        let result = xmd.expand(msg.as_bytes(), &dst, 0x20);
        assert_eq!(
            result,
            hex("20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b")
        );
    }
}
