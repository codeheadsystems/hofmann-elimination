//! RFC 9380 Appendix J.2.1 — P-256 hash_to_group test vectors.

use hofmann_rfc::elliptic_curve::{CurveType, GroupSpec, WeierstrassGroupSpec};

const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn compressed_point(prefix: u8, x_hex: &str) -> Vec<u8> {
    let mut out = vec![prefix];
    out.extend_from_slice(&hex(x_hex));
    out
}

#[test]
fn hash_to_curve_p256_empty_string() {
    let gs = WeierstrassGroupSpec::new(CurveType::P256);
    let result = gs.hash_to_group(b"", DST);
    let expected = compressed_point(
        0x03,
        "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
    );
    assert_eq!(result, expected);
}

#[test]
fn hash_to_curve_p256_abc() {
    let gs = WeierstrassGroupSpec::new(CurveType::P256);
    let result = gs.hash_to_group(b"abc", DST);
    let expected = compressed_point(
        0x02,
        "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
    );
    assert_eq!(result, expected);
}

#[test]
fn hash_to_curve_p256_abcdef0123456789() {
    let gs = WeierstrassGroupSpec::new(CurveType::P256);
    let result = gs.hash_to_group(b"abcdef0123456789", DST);
    let expected = compressed_point(
        0x03,
        "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
    );
    assert_eq!(result, expected);
}

#[test]
fn hash_to_curve_p256_q128() {
    let gs = WeierstrassGroupSpec::new(CurveType::P256);
    let mut msg = b"q128_".to_vec();
    msg.extend_from_slice(&[b'q'; 128]);
    let result = gs.hash_to_group(&msg, DST);
    let expected = compressed_point(
        0x02,
        "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
    );
    assert_eq!(result, expected);
}

#[test]
fn hash_to_curve_p256_a512() {
    let gs = WeierstrassGroupSpec::new(CurveType::P256);
    let mut msg = b"a512_".to_vec();
    msg.extend_from_slice(&[b'a'; 512]);
    let result = gs.hash_to_group(&msg, DST);
    let expected = compressed_point(
        0x02,
        "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
    );
    assert_eq!(result, expected);
}
