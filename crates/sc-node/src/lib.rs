//! NAPI-RS bindings for Signalis Core.

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

// ─── Curve25519 ─────────────────────────────────────────────────────────────

#[napi(object)]
pub struct Curve25519KeyPair {
    pub private: Buffer,
    pub public: Buffer,
}

#[napi]
pub fn curve25519_generate_keypair() -> Curve25519KeyPair {
    let kp = sc_curve25519::KeyPair::generate();
    Curve25519KeyPair {
        private: Buffer::from(kp.private.to_bytes().to_vec()),
        public: Buffer::from(kp.public.to_bytes().to_vec()),
    }
}

#[napi]
pub fn curve25519_public_from_private(private_key: Buffer) -> Result<Buffer> {
    let priv_key = sc_curve25519::PrivateKey::try_from_bytes(&private_key)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    let public = priv_key.public_key();
    Ok(Buffer::from(public.to_bytes().to_vec()))
}

#[napi]
pub fn curve25519_diffie_hellman(
    private_key: Buffer,
    peer_public_key: Buffer,
) -> Result<Buffer> {
    let priv_key = sc_curve25519::PrivateKey::try_from_bytes(&private_key)
        .map_err(|e| Error::new(Status::InvalidArg, format!("private: {e}")))?;
    let peer_pub = sc_curve25519::PublicKey::try_from_bytes(&peer_public_key)
        .map_err(|e| Error::new(Status::InvalidArg, format!("peer: {e}")))?;

    let kp = sc_curve25519::KeyPair::from_private(priv_key);
    let shared = kp.diffie_hellman(&peer_pub);

    Ok(Buffer::from(shared.to_bytes().to_vec()))
}

// ─── Ed25519 (NEW in v0.2.0) ────────────────────────────────────────────────

#[napi(object)]
pub struct Ed25519KeyPair {
    pub private: Buffer,
    pub public: Buffer,
}

#[napi]
pub fn ed25519_generate_keypair() -> Ed25519KeyPair {
    let kp = sc_ed25519::KeyPair::generate();
    Ed25519KeyPair {
        private: Buffer::from(kp.private.to_bytes().to_vec()),
        public: Buffer::from(kp.public.to_bytes().to_vec()),
    }
}

#[napi]
pub fn ed25519_keypair_from_seed(seed: Buffer) -> Result<Ed25519KeyPair> {
    let kp = sc_ed25519::KeyPair::from_seed(&seed)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Ed25519KeyPair {
        private: Buffer::from(kp.private.to_bytes().to_vec()),
        public: Buffer::from(kp.public.to_bytes().to_vec()),
    })
}

#[napi]
pub fn ed25519_public_from_private(private_key: Buffer) -> Result<Buffer> {
    let pub_bytes = sc_ed25519::public_from_private(&private_key)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(pub_bytes.to_vec()))
}

#[napi]
pub fn ed25519_sign(private_key: Buffer, message: Buffer) -> Result<Buffer> {
    let sig = sc_ed25519::sign(&private_key, &message)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(sig.to_vec()))
}

#[napi]
pub fn ed25519_verify(public_key: Buffer, message: Buffer, signature: Buffer) -> Result<()> {
    sc_ed25519::verify(&public_key, &message, &signature)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
}

#[napi]
pub fn ed25519_verify_bool(public_key: Buffer, message: Buffer, signature: Buffer) -> bool {
    sc_ed25519::verify_bool(&public_key, &message, &signature)
}

// ─── XEd25519 (NEW in v0.2.0) ───────────────────────────────────────────────

#[napi]
pub fn xed25519_sign(private_key: Buffer, message: Buffer) -> Result<Buffer> {
    let sig = sc_xed25519::sign(&private_key, &message)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(sig.to_vec()))
}

#[napi]
pub fn xed25519_sign_with_random(
    private_key: Buffer,
    message: Buffer,
    random: Buffer,
) -> Result<Buffer> {
    let sig = sc_xed25519::sign_with_random(&private_key, &message, &random)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(sig.to_vec()))
}

#[napi]
pub fn xed25519_verify(public_key: Buffer, message: Buffer, signature: Buffer) -> Result<()> {
    sc_xed25519::verify(&public_key, &message, &signature)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
}

#[napi]
pub fn xed25519_verify_bool(public_key: Buffer, message: Buffer, signature: Buffer) -> bool {
    sc_xed25519::verify_bool(&public_key, &message, &signature)
}

// ─── HKDF ───────────────────────────────────────────────────────────────────

#[napi]
pub fn hkdf_extract(salt: Buffer, ikm: Buffer) -> Buffer {
    let prk = sc_hkdf::Hkdf::extract(&salt, &ikm);
    Buffer::from(prk.to_vec())
}

#[napi]
pub fn hkdf_expand(prk: Buffer, info: Buffer, length: u32) -> Result<Buffer> {
    if prk.len() != 32 {
        return Err(Error::new(
            Status::InvalidArg,
            format!("prk must be 32 bytes, got {}", prk.len()),
        ));
    }
    let mut prk_arr = [0u8; 32];
    prk_arr.copy_from_slice(&prk);

    let okm = sc_hkdf::Hkdf::expand(&prk_arr, &info, length as usize)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(okm))
}

#[napi]
pub fn hkdf_derive(salt: Buffer, ikm: Buffer, info: Buffer, length: u32) -> Result<Buffer> {
    let okm = sc_hkdf::Hkdf::derive(&salt, &ikm, &info, length as usize)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(okm))
}

// ─── AES-256-GCM ────────────────────────────────────────────────────────────

#[napi]
pub fn aes_256_gcm_encrypt(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(Error::new(Status::InvalidArg, "nonce must be 12 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = sc_aes::Aes256GcmCipher::new(&key_arr);
    let ct = cipher
        .encrypt(&nonce_arr, &plaintext)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(ct))
}

#[napi]
pub fn aes_256_gcm_decrypt(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(Error::new(Status::InvalidArg, "nonce must be 12 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = sc_aes::Aes256GcmCipher::new(&key_arr);
    let pt = cipher
        .decrypt(&nonce_arr, &ciphertext)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

// ─── AES-256-GCM with AAD (NEW in v0.2.0) ───────────────────────────────────

#[napi]
pub fn aes_256_gcm_encrypt_with_aad(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    aad: Buffer,
) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(Error::new(Status::InvalidArg, "nonce must be 12 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = sc_aes::Aes256GcmCipher::new(&key_arr);
    let ct = cipher
        .encrypt_with_aad(&nonce_arr, &plaintext, &aad)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(ct))
}

#[napi]
pub fn aes_256_gcm_decrypt_with_aad(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    aad: Buffer,
) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(Error::new(Status::InvalidArg, "nonce must be 12 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = sc_aes::Aes256GcmCipher::new(&key_arr);
    let pt = cipher
        .decrypt_with_aad(&nonce_arr, &ciphertext, &aad)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

// ─── AES-256-CBC ────────────────────────────────────────────────────────────

#[napi]
pub fn aes_256_cbc_encrypt(key: Buffer, iv: Buffer, plaintext: Buffer) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(Error::new(Status::InvalidArg, "iv must be 16 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);

    let cipher = sc_aes::Aes256CbcCipher::new(&key_arr);
    let ct = cipher.encrypt(&iv_arr, &plaintext);
    Ok(Buffer::from(ct))
}

#[napi]
pub fn aes_256_cbc_decrypt(key: Buffer, iv: Buffer, ciphertext: Buffer) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(Error::new(Status::InvalidArg, "key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(Error::new(Status::InvalidArg, "iv must be 16 bytes"));
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);

    let cipher = sc_aes::Aes256CbcCipher::new(&key_arr);
    let pt = cipher
        .decrypt(&iv_arr, &ciphertext)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

// ─── HMAC-SHA256 ────────────────────────────────────────────────────────────

#[napi]
pub fn hmac_sha256(key: Buffer, data: Buffer) -> Buffer {
    let tag = sc_hmac::hmac_sha256(&key, &data);
    Buffer::from(tag.to_vec())
}

#[napi]
pub fn hmac_sha256_verify(key: Buffer, data: Buffer, expected_tag: Buffer) -> bool {
    sc_hmac::verify(&key, &data, &expected_tag).is_ok()
}

// ─── SHA-256 ────────────────────────────────────────────────────────────────

#[napi]
pub fn sha256(data: Buffer) -> Buffer {
    let hash = sc_sha256::sha256(&data);
    Buffer::from(hash.to_vec())
}

// ─── Version ────────────────────────────────────────────────────────────────

#[napi]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
