use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use zeroize::Zeroize;

/// Documented import and storage KDF. Kept explicit so a crate default change
/// cannot silently make existing configs undecryptable.
fn argon2() -> Result<Argon2<'static>, String> {
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| e.to_string())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

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
    argon2()?
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

    let mut key_bytes = derive_key(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed. Wrong password or corrupted file.".to_string());
    key_bytes.zeroize();
    plain
}

pub fn encrypt_for_storage(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    use rand::RngCore;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut key_bytes = derive_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| e.to_string());
    key_bytes.zeroize();
    let ciphertext = ciphertext?;

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

    let mut key_bytes = derive_key(password, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Wrong password.".to_string());
    key_bytes.zeroize();
    plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_roundtrip_and_tamper() {
        let plain = b"[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        let mut blob = encrypt_for_storage(plain, "correct horse").unwrap();
        assert_eq!(decrypt_from_storage(&blob, "correct horse").unwrap(), plain);
        assert!(decrypt_from_storage(&blob, "wrong password").is_err());
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(decrypt_from_storage(&blob, "correct horse").is_err());
    }

    #[test]
    fn import_format_matches_admin_scripts() {
        // Produced by the same argon2id (m=19456, t=2, p=1) and AES-256-GCM
        // parameters as scripts/encrypt-config.py.
        let blob = hex_decode("574743563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b1cfe74cf4152d53d39358e02b71f62285e108ed619ca69bda4387050d94e1d987b3fcb953fd2d3da0d62286100838f54ef52f40b859e5c7198cb82f051e7256c4ab7c429b15d5836d3809b20ba51505387e7150819cc");
        let plain = decrypt_imported(&blob, "test-password").unwrap();
        assert_eq!(
            plain,
            b"[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        );
        assert!(decrypt_imported(&blob, "other-password").is_err());
    }

    fn hex_decode(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }
}
