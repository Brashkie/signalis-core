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

/// HKDF-SHA512 one-shot derive (extract + expand).
#[napi]
pub fn hkdf_sha512_derive(
    salt: Buffer,
    ikm: Buffer,
    info: Buffer,
    length: u32,
) -> Result<Buffer> {
    let okm = sc_hkdf::HkdfSha512::derive(&salt, &ikm, &info, length as usize)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(okm))
}

// ─── PBKDF2-HMAC-SHA256 (NEW in v0.4.4) ─────────────────────────────────────

/// Derive a key from a password with PBKDF2-HMAC-SHA256.
#[napi]
pub fn pbkdf2_derive(
    password: Buffer,
    salt: Buffer,
    iterations: u32,
    length: u32,
) -> Result<Buffer> {
    let key = sc_pbkdf2::Pbkdf2::derive(&password, &salt, iterations, length as usize)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(key))
}

// ─── Argon2id (NEW in v0.4.6) ───────────────────────────────────────────────

/// Derive a key from a password with Argon2id (RFC 9106).
///
/// `mCost` is memory in KiB, `tCost` is iterations, `pCost` is parallelism.
#[napi]
pub fn argon2id_derive(
    password: Buffer,
    salt: Buffer,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    length: u32,
) -> Result<Buffer> {
    let key = sc_argon2::Argon2id::derive(
        &password,
        &salt,
        m_cost,
        t_cost,
        p_cost,
        length as usize,
    )
    .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(key))
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

#[napi]
pub fn hmac_sha512(key: Buffer, data: Buffer) -> Buffer {
    let tag = sc_hmac::hmac_sha512(&key, &data);
    Buffer::from(tag.to_vec())
}

#[napi]
pub fn hmac_sha512_verify(key: Buffer, data: Buffer, expected_tag: Buffer) -> bool {
    sc_hmac::verify_sha512(&key, &data, &expected_tag).is_ok()
}

// ─── SHA-256 ────────────────────────────────────────────────────────────────

#[napi]
pub fn sha256(data: Buffer) -> Buffer {
    let hash = sc_sha256::sha256(&data);
    Buffer::from(hash.to_vec())
}

// ─── ChaCha20-Poly1305 (NEW in v0.3.0) ──────────────────────────────────────

#[napi]
pub fn chacha20_poly1305_encrypt(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
) -> Result<Buffer> {
    let ct = sc_chacha20poly1305::encrypt(&key, &nonce, &plaintext)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(ct))
}

#[napi]
pub fn chacha20_poly1305_decrypt(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
) -> Result<Buffer> {
    let pt = sc_chacha20poly1305::decrypt(&key, &nonce, &ciphertext)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

#[napi]
pub fn chacha20_poly1305_encrypt_with_aad(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    aad: Buffer,
) -> Result<Buffer> {
    let ct = sc_chacha20poly1305::encrypt_with_aad(&key, &nonce, &plaintext, &aad)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(ct))
}

#[napi]
pub fn chacha20_poly1305_decrypt_with_aad(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    aad: Buffer,
) -> Result<Buffer> {
    let pt = sc_chacha20poly1305::decrypt_with_aad(&key, &nonce, &ciphertext, &aad)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

// ─── XChaCha20-Poly1305 (24-byte nonce, NEW in v0.4.3) ──────────────────────

#[napi]
pub fn xchacha20_poly1305_encrypt(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
) -> Result<Buffer> {
    let ct = sc_chacha20poly1305::xchacha_encrypt(&key, &nonce, &plaintext)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(ct))
}

#[napi]
pub fn xchacha20_poly1305_decrypt(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
) -> Result<Buffer> {
    let pt = sc_chacha20poly1305::xchacha_decrypt(&key, &nonce, &ciphertext)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

#[napi]
pub fn xchacha20_poly1305_encrypt_with_aad(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    aad: Buffer,
) -> Result<Buffer> {
    let ct = sc_chacha20poly1305::xchacha_encrypt_with_aad(&key, &nonce, &plaintext, &aad)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(ct))
}

#[napi]
pub fn xchacha20_poly1305_decrypt_with_aad(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    aad: Buffer,
) -> Result<Buffer> {
    let pt = sc_chacha20poly1305::xchacha_decrypt_with_aad(&key, &nonce, &ciphertext, &aad)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    Ok(Buffer::from(pt))
}

// ─── Utility helpers (NEW in v0.3.0) ────────────────────────────────────────

/// Generate `size` cryptographically secure random bytes.
///
/// Backed by the OS random number generator (getrandom/BCryptGenRandom/
/// SecRandomCopyBytes depending on platform).
#[napi]
pub fn secure_random(size: u32) -> Result<Buffer> {
    let bytes = sc_utils::random_bytes(size as usize)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
    Ok(Buffer::from(bytes))
}

/// Compare two buffers in constant time.
///
/// Returns `true` only if both buffers have identical length AND contents.
/// Use this for comparing MACs, signatures, or any secret value where
/// timing-based comparison could leak information.
#[napi]
pub fn constant_time_eq(a: Buffer, b: Buffer) -> bool {
    sc_utils::constant_time_eq(&a, &b)
}

// ─── Encoding helpers (NEW in v0.4.0) ───────────────────────────────────────

/// Encode bytes to standard Base64 (RFC 4648, with `=` padding).
#[napi]
pub fn base64_encode(input: Buffer) -> String {
    sc_encoding::base64::encode(&input)
}

/// Decode a standard Base64 string back to bytes.
///
/// Throws if the input contains invalid characters, incorrect padding, or wrong length.
#[napi]
pub fn base64_decode(input: String) -> Result<Buffer> {
    sc_encoding::base64::decode(&input)
        .map(Buffer::from)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))
}

/// Encode bytes to URL-safe Base64 without padding (RFC 4648 §5).
///
/// Uses `-` and `_` instead of `+` and `/`. Safe to include in URLs,
/// filenames, and HTTP headers as-is.
#[napi]
pub fn base64_encode_url_safe(input: Buffer) -> String {
    sc_encoding::base64::encode_url_safe(&input)
}

/// Decode a URL-safe Base64 string (no padding) back to bytes.
#[napi]
pub fn base64_decode_url_safe(input: String) -> Result<Buffer> {
    sc_encoding::base64::decode_url_safe(&input)
        .map(Buffer::from)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))
}

/// Encode bytes to a lowercase hex string.
#[napi]
pub fn hex_encode(input: Buffer) -> String {
    sc_encoding::hex::encode(&input)
}

/// Encode bytes to an uppercase hex string.
#[napi]
pub fn hex_encode_upper(input: Buffer) -> String {
    sc_encoding::hex::encode_upper(&input)
}

/// Decode a hex string back to bytes. Case-insensitive.
///
/// Throws if the string has an odd number of characters or contains non-hex characters.
#[napi]
pub fn hex_decode(input: String) -> Result<Buffer> {
    sc_encoding::hex::decode(&input)
        .map(Buffer::from)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))
}

/// Check whether the given string is well-formed hex (even length, only 0-9/a-f/A-F).
#[napi]
pub fn hex_is_valid(input: String) -> bool {
    sc_encoding::hex::is_valid(&input)
}

/// Encode a string to its UTF-8 byte representation.
#[napi]
pub fn utf8_encode(input: String) -> Buffer {
    Buffer::from(sc_encoding::utf8::encode(&input))
}

/// Decode UTF-8 bytes to a string. Throws on invalid UTF-8.
#[napi]
pub fn utf8_decode(input: Buffer) -> Result<String> {
    sc_encoding::utf8::decode(&input)
        .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))
}

/// Check whether the given bytes are valid UTF-8.
#[napi]
pub fn utf8_is_valid(input: Buffer) -> bool {
    sc_encoding::utf8::is_valid(&input)
}

// ─── Version ────────────────────────────────────────────────────────────────

#[napi]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
