//! RFC 9497 OPRF test vectors for all four cipher suites.
//!
//! P256-SHA256, P384-SHA384, P521-SHA512 vectors from RFC 9497 Appendix A.
//! Ristretto255-SHA512 vectors from CFRG allVectors.json.

use hofmann_rfc::oprf::{CurveHashSuite, OprfCipherSuite};

/// Decode a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ============================================================
// P256-SHA256 (RFC 9497 Appendix A.1.1)
// ============================================================

mod p256_sha256 {
    use super::*;

    fn suite() -> OprfCipherSuite {
        OprfCipherSuite::new(CurveHashSuite::P256Sha256)
    }

    fn seed() -> Vec<u8> {
        vec![0xa3u8; 32]
    }

    #[test]
    fn test_derive_key_pair() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        assert_eq!(
            sk_s,
            hex("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf")
        );
    }

    #[test]
    fn test_dst_strings() {
        let oprf = suite();
        assert_eq!(
            oprf.context_string(),
            &hex("4f50524656312d002d503235362d534841323536")[..]
        );
        assert_eq!(
            oprf.hash_to_group_dst(),
            &hex("48617368546f47726f75702d4f50524656312d002d503235362d534841323536")[..]
        );
        assert_eq!(
            oprf.hash_to_scalar_dst(),
            &hex("48617368546f5363616c61722d4f50524656312d002d503235362d534841323536")[..]
        );
        assert_eq!(
            oprf.derive_key_pair_dst(),
            &hex("4465726976654b6579506169724f50524656312d002d503235362d534841323536")[..]
        );
    }

    #[test]
    fn test_vector_1() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x00u8];
        let blind = hex("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd")
        );
    }

    #[test]
    fn test_vector_2() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x5au8; 17];
        let blind = hex("e6d0f1d89ad552e859d708177054aca4695ef33b5d89d4d3f9a2c376e08a1450");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        let evaluated = gs.scalar_multiply(&sk_s, &blinded);

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce")
        );
    }
}

// ============================================================
// P384-SHA384 (RFC 9497 Appendix A.2.1)
// ============================================================

mod p384_sha384 {
    use super::*;

    fn suite() -> OprfCipherSuite {
        OprfCipherSuite::new(CurveHashSuite::P384Sha384)
    }

    fn seed() -> Vec<u8> {
        vec![0xa3u8; 32]
    }

    #[test]
    fn test_derive_key_pair() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        assert_eq!(
            sk_s,
            hex("dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188")
        );
    }

    #[test]
    fn test_vector_1() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x00u8];
        let blind = hex("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("02a36bc90e6db34096346eaf8b7bc40ee1113582155ad3797003ce614c835a874343701d3f2debbd80d97cbe45de6e5f1f")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("03af2a4fc94770d7a7bf3187ca9cc4faf3732049eded2442ee50fbddda58b70ae2999366f72498cdbc43e6f2fc184afe30")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("ed84ad3f31a552f0456e58935fcc0a3039db42e7f356dcb32aa6d487b6b815a07d5813641fb1398c03ddab5763874357")
        );
    }

    #[test]
    fn test_vector_2() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x5au8; 17];
        let blind = hex("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("02def6f418e3484f67a124a2ce1bfb19de7a4af568ede6a1ebb2733882510ddd43d05f2b1ab5187936a55e50a847a8b900")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("034e9b9a2960b536f2ef47d8608b21597ba400d5abfa1825fd21c36b75f927f396bf3716c96129d1fa4a77fa1d479c8d7b")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("dd4f29da869ab9355d60617b60da0991e22aaab243a3460601e48b075859d1c526d36597326f1b985778f781a1682e75")
        );
    }
}

// ============================================================
// P521-SHA512 (RFC 9497 Appendix A.3.1)
// ============================================================

mod p521_sha512 {
    use super::*;

    fn suite() -> OprfCipherSuite {
        OprfCipherSuite::new(CurveHashSuite::P521Sha512)
    }

    fn seed() -> Vec<u8> {
        vec![0xa3u8; 32]
    }

    #[test]
    fn test_derive_key_pair() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        assert_eq!(
            sk_s,
            hex("0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6")
        );
    }

    #[test]
    fn test_vector_1() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x00u8];
        let blind = hex("00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("0300e78bf846b0e1e1a3c320e353d758583cd876df56100a3a1e62bacba470fa6e0991be1be80b721c50c5fd0c672ba764457acc18c6200704e9294fbf28859d916351")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("030166371cf827cb2fb9b581f97907121a16e2dc5d8b10ce9f0ede7f7d76a0d047657735e8ad07bcda824907b3e5479bd72cdef6b839b967ba5c58b118b84d26f2ba07")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("26232de6fff83f812adadadb6cc05d7bbeee5dca043dbb16b03488abb9981d0a1ef4351fad52dbd7e759649af393348f7b9717566c19a6b8856284d69375c809")
        );
    }

    #[test]
    fn test_vector_2() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x5au8; 17];
        let blind = hex("00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("0300c28e57e74361d87e0c1874e5f7cc1cc796d61f9cad50427cf54655cdb455613368d42b27f94bf66f59f53c816db3e95e68e1b113443d66a99b3693bab88afb556b")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("0301ad453607e12d0cc11a3359332a40c3a254eaa1afc64296528d55bed07ba322e72e22cf3bcb50570fd913cb54f7f09c17aff8787af75f6a7faf5640cbb2d9620a6e")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("ad1f76ef939042175e007738906ac0336bbd1d51e287ebaa66901abdd324ea3ffa40bfc5a68e7939c2845e0fd37a5a6e76dadb9907c6cc8579629757fd4d04ba")
        );
    }
}

// ============================================================
// Ristretto255-SHA512 (CFRG allVectors.json)
// ============================================================

mod ristretto255_sha512 {
    use super::*;

    fn suite() -> OprfCipherSuite {
        OprfCipherSuite::new(CurveHashSuite::Ristretto255Sha512)
    }

    fn seed() -> Vec<u8> {
        vec![0xa3u8; 32]
    }

    #[test]
    fn test_derive_key_pair() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        assert_eq!(
            sk_s,
            hex("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")
        );
    }

    #[test]
    fn test_vector_1() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x00u8];
        let blind = hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")
        );
    }

    #[test]
    fn test_vector_2() {
        let oprf = suite();
        let sk_s = oprf.derive_key_pair(&seed(), b"test key");
        let gs = oprf.group_spec();

        let input = vec![0x5au8; 17];
        let blind = hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");

        let hashed = gs.hash_to_group(&input, oprf.hash_to_group_dst());
        let blinded = gs.scalar_multiply(&blind, &hashed);
        assert_eq!(
            blinded,
            hex("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418")
        );

        let evaluated = gs.scalar_multiply(&sk_s, &blinded);
        assert_eq!(
            evaluated,
            hex("b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25")
        );

        let output = oprf.finalize(&input, &blind, &evaluated);
        assert_eq!(
            output,
            hex("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73")
        );
    }
}
