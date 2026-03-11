use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use rand::rngs::OsRng;

pub const MAGIC_IMPORT: &[u8] = b"WGCV1\0";

pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC_IMPORT)
}

pub fn is_plain_wireguard(data: &[u8]) -> bool {
    std::str::from_utf8(data)
        .map(|s| s.contains("[Interface]"))
        .unwrap_or(false)
}
const MAGIC_STORE: &[u8] = b"WGCSI\0";

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn decrypt_imported(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let header = MAGIC_IMPORT.len() + SALT_LEN + NONCE_LEN;
    if data.len() < header + 1 {
        return Err("Invalid or corrupted file format.".into());
    }
    if &data[..MAGIC_IMPORT.len()] != MAGIC_IMPORT {
        return Err("Not a valid encrypted WireGuard config. Wrong file or format.".into());
    }

    let offset = MAGIC_IMPORT.len();
    let salt = &data[offset..offset + SALT_LEN];
    let nonce_bytes = &data[offset + SALT_LEN..offset + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[offset + SALT_LEN + NONCE_LEN..];

    let key_bytes = derive_key(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed. Wrong password or corrupted file.".into())
}

pub fn encrypt_for_storage(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    use rand::RngCore;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key_bytes = derive_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| e.to_string())?;

    let mut result = Vec::with_capacity(MAGIC_STORE.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(MAGIC_STORE);
    result.extend_from_slice(&salt);
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_from_storage(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let header = MAGIC_STORE.len() + SALT_LEN + NONCE_LEN;
    if data.len() < header + 1 {
        return Err("Stored config is corrupted.".into());
    }
    if &data[..MAGIC_STORE.len()] != MAGIC_STORE {
        return Err("Stored config format is invalid.".into());
    }

    let offset = MAGIC_STORE.len();
    let salt = &data[offset..offset + SALT_LEN];
    let nonce_bytes = &data[offset + SALT_LEN..offset + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[offset + SALT_LEN + NONCE_LEN..];

    let key_bytes = derive_key(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Wrong password.".into())
}
