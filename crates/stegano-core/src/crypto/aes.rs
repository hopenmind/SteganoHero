//! AES-GCM Authenticated Encryption — port fidèle du plugin Python SteganoHero-v1.
//!
//! Supporte AES-128-GCM, AES-192-GCM et AES-256-GCM.
//! Dérivation de clé : Argon2id (résistant GPU/ASIC).
//! Nonce : 96 bits aléatoires (jamais déterministe).
//!
//! Format de sortie : VERSION(1) || KEY_SIZE(1) || SALT(16) || NONCE(12) || CIPHERTEXT || TAG(16)

use crate::crypto::keytree::note_argon2_derivation;
use crate::error::{Result, SteganoError};
use crate::traits::{CryptoMethod, KeyedCryptoMethod};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes128Gcm, Aes256Gcm, Nonce,
};
use argon2::Argon2;

const VERSION: u8 = 0x01;
/// Marks the key-tree format: `KEYED_VERSION || NONCE || CIPHERTEXT+TAG`.
/// Distinct from `VERSION` so the two formats can never be read for each other.
const KEYED_VERSION: u8 = 0x10;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// ─── AES-256-GCM (le principal, port du Python) ───

pub struct Aes256;

impl Aes256 {
    pub fn new() -> Self {
        Self
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| SteganoError::EncryptionFailed(format!("key derivation failed: {e}")))?;
        note_argon2_derivation();
        Ok(key)
    }
}

impl KeyedCryptoMethod for Aes256 {
    fn id(&self) -> &str {
        "aes256_gcm"
    }

    fn key_len(&self) -> usize {
        32
    }

    fn encrypt_with_key(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(SteganoError::InvalidInput(format!(
                "aes256_gcm: key must be {} bytes, got {}",
                self.key_len(),
                key.len()
            )));
        }

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        output.push(KEYED_VERSION);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt_with_key(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(SteganoError::InvalidInput(format!(
                "aes256_gcm: key must be {} bytes, got {}",
                self.key_len(),
                key.len()
            )));
        }
        if ciphertext.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err(SteganoError::DecryptionFailed);
        }
        if ciphertext[0] != KEYED_VERSION {
            return Err(SteganoError::DecodingFailed {
                method: "aes256_gcm".into(),
                reason: format!(
                    "not a key-tree ciphertext: version byte 0x{:02x}",
                    ciphertext[0]
                ),
            });
        }

        let nonce = Nonce::from_slice(&ciphertext[1..1 + NONCE_LEN]);
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        cipher
            .decrypt(nonce, &ciphertext[1 + NONCE_LEN..])
            .map_err(|_| SteganoError::DecryptionFailed)
    }
}

impl CryptoMethod for Aes256 {
    fn id(&self) -> &str {
        "aes256_gcm"
    }

    fn name(&self) -> &str {
        "AES-256-GCM (Argon2id)"
    }

    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
        if password.is_empty() {
            return Err(SteganoError::InvalidInput("password cannot be empty".into()));
        }

        let salt: [u8; SALT_LEN] = rand::random();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let key = Self::derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        // Pack: VERSION || KEY_SIZE(32) || SALT || NONCE || CIPHERTEXT+TAG
        let mut output = Vec::with_capacity(2 + SALT_LEN + NONCE_LEN + ciphertext.len());
        output.push(VERSION);
        output.push(32); // key size marker
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
        let min_len = 2 + SALT_LEN + NONCE_LEN + 16; // header + tag
        if ciphertext.len() < min_len {
            return Err(SteganoError::DecryptionFailed);
        }

        if ciphertext[0] != VERSION || ciphertext[1] != 32 {
            return Err(SteganoError::DecodingFailed {
                method: "aes256_gcm".into(),
                reason: format!("unsupported version/key_size: 0x{:02x}/{}",
                    ciphertext[0], ciphertext[1]),
            });
        }

        let salt = &ciphertext[2..2 + SALT_LEN];
        let nonce_bytes = &ciphertext[2 + SALT_LEN..2 + SALT_LEN + NONCE_LEN];
        let encrypted = &ciphertext[2 + SALT_LEN + NONCE_LEN..];

        let nonce = Nonce::from_slice(nonce_bytes);
        let key = Self::derive_key(password, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| SteganoError::DecryptionFailed)
    }
}

// ─── AES-128-GCM (léger, pour les cas où la vitesse prime) ───

pub struct Aes128;

impl Aes128 {
    pub fn new() -> Self {
        Self
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 16]> {
        let mut key = [0u8; 16];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| SteganoError::EncryptionFailed(format!("key derivation failed: {e}")))?;
        note_argon2_derivation();
        Ok(key)
    }
}

impl KeyedCryptoMethod for Aes128 {
    fn id(&self) -> &str {
        "aes128_gcm"
    }

    fn key_len(&self) -> usize {
        16
    }

    fn encrypt_with_key(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(SteganoError::InvalidInput(format!(
                "aes128_gcm: key must be {} bytes, got {}",
                self.key_len(),
                key.len()
            )));
        }

        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        output.push(KEYED_VERSION);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt_with_key(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(SteganoError::InvalidInput(format!(
                "aes128_gcm: key must be {} bytes, got {}",
                self.key_len(),
                key.len()
            )));
        }
        if ciphertext.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err(SteganoError::DecryptionFailed);
        }
        if ciphertext[0] != KEYED_VERSION {
            return Err(SteganoError::DecodingFailed {
                method: "aes128_gcm".into(),
                reason: format!(
                    "not a key-tree ciphertext: version byte 0x{:02x}",
                    ciphertext[0]
                ),
            });
        }

        let nonce = Nonce::from_slice(&ciphertext[1..1 + NONCE_LEN]);
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        cipher
            .decrypt(nonce, &ciphertext[1 + NONCE_LEN..])
            .map_err(|_| SteganoError::DecryptionFailed)
    }
}

impl CryptoMethod for Aes128 {
    fn id(&self) -> &str {
        "aes128_gcm"
    }

    fn name(&self) -> &str {
        "AES-128-GCM (Argon2id)"
    }

    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
        if password.is_empty() {
            return Err(SteganoError::InvalidInput("password cannot be empty".into()));
        }

        let salt: [u8; SALT_LEN] = rand::random();
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);

        let key = Self::derive_key(password, &salt)?;
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(2 + SALT_LEN + NONCE_LEN + ciphertext.len());
        output.push(VERSION);
        output.push(16); // key size marker
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
        let min_len = 2 + SALT_LEN + NONCE_LEN + 16;
        if ciphertext.len() < min_len {
            return Err(SteganoError::DecryptionFailed);
        }

        if ciphertext[0] != VERSION || ciphertext[1] != 16 {
            return Err(SteganoError::DecodingFailed {
                method: "aes128_gcm".into(),
                reason: format!("unsupported version/key_size: 0x{:02x}/{}",
                    ciphertext[0], ciphertext[1]),
            });
        }

        let salt = &ciphertext[2..2 + SALT_LEN];
        let nonce_bytes = &ciphertext[2 + SALT_LEN..2 + SALT_LEN + NONCE_LEN];
        let encrypted = &ciphertext[2 + SALT_LEN + NONCE_LEN..];

        let nonce = Nonce::from_slice(nonce_bytes);
        let key = Self::derive_key(password, salt)?;
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| SteganoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keytree::argon2_derivation_count;

    // ─── AES-256 ───

    #[test]
    fn aes256_roundtrip() {
        let a = Aes256::new();
        let plaintext = b"SteganoHero secret message via AES-256!";
        let password = "correct horse battery staple";
        let encrypted = a.encrypt(plaintext, password).unwrap();
        let decrypted = a.decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256_wrong_password() {
        let a = Aes256::new();
        let encrypted = a.encrypt(b"secret", "right").unwrap();
        assert!(a.decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn aes256_nondeterministic() {
        let a = Aes256::new();
        let enc1 = a.encrypt(b"same", "same").unwrap();
        let enc2 = a.encrypt(b"same", "same").unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn aes256_tamper_detection() {
        let a = Aes256::new();
        let mut encrypted = a.encrypt(b"message", "password").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(a.decrypt(&encrypted, "password").is_err());
    }

    #[test]
    fn aes256_empty_password_rejected() {
        let a = Aes256::new();
        assert!(a.encrypt(b"data", "").is_err());
    }

    // ─── AES-128 ───

    #[test]
    fn aes128_roundtrip() {
        let a = Aes128::new();
        let plaintext = b"AES-128 test";
        let password = "password123";
        let encrypted = a.encrypt(plaintext, password).unwrap();
        let decrypted = a.decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes128_wrong_password() {
        let a = Aes128::new();
        let encrypted = a.encrypt(b"data", "right").unwrap();
        assert!(a.decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn aes128_nondeterministic() {
        let a = Aes128::new();
        let enc1 = a.encrypt(b"same", "pw").unwrap();
        let enc2 = a.encrypt(b"same", "pw").unwrap();
        assert_ne!(enc1, enc2);
    }

    // ─── Keyed path (SPEC_CORE_V2 §2) ───

    #[test]
    fn aes256_keyed_roundtrip() {
        let a = Aes256::new();
        let key = [9u8; 32];
        let plaintext = b"keyed AES-256 payload";
        let encrypted = a.encrypt_with_key(plaintext, &key).unwrap();
        let decrypted = a.decrypt_with_key(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes128_keyed_roundtrip() {
        let a = Aes128::new();
        let key = [4u8; 16];
        let plaintext = b"keyed AES-128 payload";
        let encrypted = a.encrypt_with_key(plaintext, &key).unwrap();
        let decrypted = a.decrypt_with_key(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256_keyed_wrong_key_fails() {
        let a = Aes256::new();
        let encrypted = a.encrypt_with_key(b"secret", &[1u8; 32]).unwrap();
        assert!(matches!(
            a.decrypt_with_key(&encrypted, &[2u8; 32]),
            Err(SteganoError::DecryptionFailed)
        ));
    }

    #[test]
    fn aes256_keyed_rejects_wrong_key_length() {
        let a = Aes256::new();
        assert!(matches!(
            a.encrypt_with_key(b"secret", &[0u8; 16]),
            Err(SteganoError::InvalidInput(_))
        ));
    }

    #[test]
    fn aes256_keyed_output_carries_no_salt() {
        // Keyed format: KEYED_VERSION || NONCE || CIPHERTEXT+TAG.
        // The salt belongs to the document, not to every cipher's output.
        let a = Aes256::new();
        let plaintext = b"12345678";
        let encrypted = a.encrypt_with_key(plaintext, &[1u8; 32]).unwrap();
        assert_eq!(encrypted[0], KEYED_VERSION);
        assert_eq!(encrypted.len(), 1 + NONCE_LEN + plaintext.len() + 16);
    }

    #[test]
    fn aes256_keyed_path_runs_no_argon2() {
        let a = Aes256::new();
        let before = argon2_derivation_count();
        let encrypted = a.encrypt_with_key(b"payload", &[5u8; 32]).unwrap();
        a.decrypt_with_key(&encrypted, &[5u8; 32]).unwrap();
        assert_eq!(argon2_derivation_count() - before, 0);
    }

    #[test]
    fn aes256_password_path_still_derives_per_call() {
        let a = Aes256::new();
        let encrypted = a.encrypt(b"payload", "password").unwrap();
        let before = argon2_derivation_count();
        a.decrypt(&encrypted, "password").unwrap();
        a.decrypt(&encrypted, "password").unwrap();
        assert_eq!(argon2_derivation_count() - before, 2);
    }

    #[test]
    fn aes256_keyed_and_password_formats_do_not_cross() {
        let a = Aes256::new();
        let keyed = a.encrypt_with_key(b"payload", &[6u8; 32]).unwrap();
        let salted = a.encrypt(b"payload", "password").unwrap();

        assert!(a.decrypt(&keyed, "password").is_err());
        assert!(a.decrypt_with_key(&salted, &[6u8; 32]).is_err());
    }
}
