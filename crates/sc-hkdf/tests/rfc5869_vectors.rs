//! Tests with official RFC 5869 HKDF-SHA256 test vectors.

use hex_literal::hex;
use sc_hkdf::Hkdf;

#[test]
fn rfc5869_test_case_1() {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;

    let expected_prk =
        hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let expected_okm = hex!(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    );

    let prk = Hkdf::extract(&salt, &ikm);
    assert_eq!(prk, expected_prk);

    let okm = Hkdf::expand(&prk, &info, length).expect("valid");
    assert_eq!(okm, expected_okm);
}

#[test]
fn rfc5869_test_case_3() {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = b"";
    let info = b"";
    let length = 42;

    let expected_prk =
        hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    let expected_okm = hex!(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    );

    let prk = Hkdf::extract(salt, &ikm);
    assert_eq!(prk, expected_prk);

    let okm = Hkdf::expand(&prk, info, length).expect("valid");
    assert_eq!(okm, expected_okm);
}
