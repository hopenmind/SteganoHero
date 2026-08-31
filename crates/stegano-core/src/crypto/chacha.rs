use crate::crypto::keytree::note_argon2_derivation;
use crate::error::{Result, SteganoError};
use crate::traits::{CryptoMethod, KeyedCryptoMethod};

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, ChaCha20Poly1305, Key, Nonce,
};

/// ChaCha20-Poly1305 Authenticated Encryption
///
/// Key derivation: Argon2id (memory-hard, resistant to GPU/ASIC attacks)
/// Nonce: 12 random bytes (NEVER deterministic)
/// Authentication: Poly1305 MAC (detects tampering + wrong password)
///
/// Output format: VERSION(1) || SALT(16) || NONCE(12) || CIPHERTEXT || TAG(16)
const VERSION: u8 = 0x02; // v2 = salted Argon2
/// Marks the key-tree format: `KEYED_VERSION || NONCE || CIPHERTEXT+TAG`.
/// Distinct from `VERSION` so the two formats can never be read for each other.
const KEYED_VERSION: u8 = 0x10;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub struct ChaCha20;

impl ChaCha20 {
    pub fn new() -> Self {
        Self
    }

    /// Derive a 256-bit key from password + salt using Argon2id.
    fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| SteganoError::EncryptionFailed(format!("key derivation failed: {e}")))?;
        note_argon2_derivation();
        Ok(*Key::from_slice(&key_bytes))
    }
}

impl KeyedCryptoMethod for ChaCha20 {
    fn id(&self) -> &str {
        "chacha20_poly1305"
    }

    fn key_len(&self) -> usize {
        32
    }

    fn encrypt_with_key(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if key.len() != self.key_len() {
            return Err(SteganoError::InvalidInput(format!(
                "chacha20_poly1305: key must be {} bytes, got {}",
                self.key_len(),
                key.len()
            )));
        }

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

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
                "chacha20_poly1305: key must be {} bytes, got {}",
                self.key_len(),
                key.len()
            )));
        }
        if ciphertext.len() < 1 + NONCE_LEN + TAG_LEN {
            return Err(SteganoError::DecryptionFailed);
        }
        if ciphertext[0] != KEYED_VERSION {
            return Err(SteganoError::DecodingFailed {
                method: "chacha20_poly1305".into(),
                reason: format!(
                    "not a key-tree ciphertext: version byte 0x{:02x}",
                    ciphertext[0]
                ),
            });
        }

        let nonce = Nonce::from_slice(&ciphertext[1..1 + NONCE_LEN]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

        cipher
            .decrypt(nonce, &ciphertext[1 + NONCE_LEN..])
            .map_err(|_| SteganoError::DecryptionFailed)
    }
}

impl CryptoMethod for ChaCha20 {
    fn id(&self) -> &str {
        "chacha20_poly1305"
    }

    fn name(&self) -> &str {
        "ChaCha20-Poly1305 (Argon2id)"
    }

    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
        if password.is_empty() {
            return Err(SteganoError::InvalidInput("password cannot be empty".into()));
        }

        // Generate random salt and nonce
        let salt: [u8; SALT_LEN] = rand::random();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Derive key
        let key = Self::derive_key(password, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key);

        // Encrypt (includes Poly1305 authentication tag)
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SteganoError::EncryptionFailed(e.to_string()))?;

        // Pack: VERSION || SALT || NONCE || CIPHERTEXT+TAG
        let mut output = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        output.push(VERSION);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
        let min_len = 1 + SALT_LEN + NONCE_LEN + 16; // version + salt + nonce + tag
        if ciphertext.len() < min_len {
            return Err(SteganoError::DecryptionFailed);
        }

        let version = ciphertext[0];
        if version != VERSION {
            return Err(SteganoError::DecodingFailed {
                method: "chacha20".into(),
                reason: format!("unsupported version byte: 0x{version:02x}"),
            });
        }

        let salt = &ciphertext[1..1 + SALT_LEN];
        let nonce_bytes = &ciphertext[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];
        let encrypted = &ciphertext[1 + SALT_LEN + NONCE_LEN..];

        let nonce = Nonce::from_slice(nonce_bytes);
        let key = Self::derive_key(password, salt)?;
        let cipher = ChaCha20Poly1305::new(&key);

        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| SteganoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keytree::argon2_derivation_count;

    #[test]
    fn roundtrip() {
        let cc = ChaCha20::new();
        let plaintext = b"SteganoHero secret message!";
        let password = "correct horse battery staple";

        let encrypted = cc.encrypt(plaintext, password).unwrap();
        let decrypted = cc.decrypt(&encrypted, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let cc = ChaCha20::new();
        let encrypted = cc.encrypt(b"secret", "right_password").unwrap();

        let result = cc.decrypt(&encrypted, "wrong_password");
        assert!(matches!(result, Err(SteganoError::DecryptionFailed)));
    }

    #[test]
    fn nondeterministic() {
        let cc = ChaCha20::new();
        let plaintext = b"same message";
        let password = "same password";

        let enc1 = cc.encrypt(plaintext, password).unwrap();
        let enc2 = cc.encrypt(plaintext, password).unwrap();

        // Same plaintext + password MUST produce different ciphertexts
        assert_ne!(enc1, enc2, "encryption must be non-deterministic!");

        // But both must decrypt to the same plaintext
        assert_eq!(cc.decrypt(&enc1, password).unwrap(), plaintext);
        assert_eq!(cc.decrypt(&enc2, password).unwrap(), plaintext);
    }

    #[test]
    fn tamper_detection() {
        let cc = ChaCha20::new();
        let mut encrypted = cc.encrypt(b"message", "password").unwrap();

        // Flip a bit in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        // Poly1305 should catch the tamper
        assert!(cc.decrypt(&encrypted, "password").is_err());
    }

    #[test]
    fn empty_password_rejected() {
        let cc = ChaCha20::new();
        assert!(cc.encrypt(b"data", "").is_err());
    }

    #[test]
    fn version_byte_present() {
        let cc = ChaCha20::new();
        let encrypted = cc.encrypt(b"test", "pass").unwrap();
        assert_eq!(encrypted[0], VERSION);
    }

    // ─── Keyed path (SPEC_CORE_V2 §2) ───

    #[test]
    fn keyed_roundtrip() {
        let cc = ChaCha20::new();
        let key = [3u8; 32];
        let plaintext = b"keyed ChaCha20 payload";
        let encrypted = cc.encrypt_with_key(plaintext, &key).unwrap();
        let decrypted = cc.decrypt_with_key(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn keyed_wrong_key_fails() {
        let cc = ChaCha20::new();
        let encrypted = cc.encrypt_with_key(b"secret", &[1u8; 32]).unwrap();
        assert!(matches!(
            cc.decrypt_with_key(&encrypted, &[2u8; 32]),
            Err(SteganoError::DecryptionFailed)
        ));
    }

    #[test]
    fn keyed_output_carries_no_salt() {
        let cc = ChaCha20::new();
        let plaintext = b"12345678";
        let encrypted = cc.encrypt_with_key(plaintext, &[7u8; 32]).unwrap();
        assert_eq!(encrypted[0], KEYED_VERSION);
        assert_eq!(encrypted.len(), 1 + NONCE_LEN + plaintext.len() + 16);
    }

    #[test]
    fn keyed_path_runs_no_argon2() {
        let cc = ChaCha20::new();
        let before = argon2_derivation_count();
        let encrypted = cc.encrypt_with_key(b"payload", &[8u8; 32]).unwrap();
        cc.decrypt_with_key(&encrypted, &[8u8; 32]).unwrap();
        assert_eq!(argon2_derivation_count() - before, 0);
    }

    #[test]
    fn keyed_and_password_formats_do_not_cross() {
        let cc = ChaCha20::new();
        let keyed = cc.encrypt_with_key(b"payload", &[6u8; 32]).unwrap();
        let salted = cc.encrypt(b"payload", "password").unwrap();

        assert!(cc.decrypt(&keyed, "password").is_err());
        assert!(cc.decrypt_with_key(&salted, &[6u8; 32]).is_err());
    }
}
