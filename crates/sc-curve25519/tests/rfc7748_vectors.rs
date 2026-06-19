//! Tests with official RFC 7748 X25519 test vectors.

use hex_literal::hex;
use sc_curve25519::{KeyPair, PrivateKey, PublicKey};

#[test]
fn rfc7748_test_vector_1() {
    let scalar = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u_coord = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected = hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    let private = PrivateKey::try_from_bytes(&scalar).expect("valid scalar");
    let kp = KeyPair::from_private(private);

    let peer = PublicKey::from_bytes(&u_coord);
    let shared = kp.diffie_hellman(&peer);

    assert_eq!(shared.as_bytes(), &expected, "RFC 7748 vector 1 failed");
}

#[test]
fn rfc7748_test_vector_2() {
    let scalar = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u_coord = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let expected = hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    let private = PrivateKey::try_from_bytes(&scalar).expect("valid scalar");
    let kp = KeyPair::from_private(private);

    let peer = PublicKey::from_bytes(&u_coord);
    let shared = kp.diffie_hellman(&peer);

    assert_eq!(shared.as_bytes(), &expected, "RFC 7748 vector 2 failed");
}

#[test]
fn rfc7748_alice_bob_ecdh() {
    let alice_private = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public_expected =
        hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    let bob_private = hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_public_expected =
        hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    let shared_expected = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let alice_priv = PrivateKey::try_from_bytes(&alice_private).expect("valid");
    let alice_kp = KeyPair::from_private(alice_priv);
    assert_eq!(alice_kp.public.as_bytes(), &alice_public_expected);

    let bob_priv = PrivateKey::try_from_bytes(&bob_private).expect("valid");
    let bob_kp = KeyPair::from_private(bob_priv);
    assert_eq!(bob_kp.public.as_bytes(), &bob_public_expected);

    let alice_shared = alice_kp.diffie_hellman(&bob_kp.public);
    let bob_shared = bob_kp.diffie_hellman(&alice_kp.public);

    assert_eq!(alice_shared.as_bytes(), &shared_expected);
    assert_eq!(bob_shared.as_bytes(), &shared_expected);
}
