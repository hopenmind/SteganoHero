//! Caesar/XOR cipher — port fidèle du plugin Python SteganoHero-v1.
//!
//! Dérive une clé de la longueur des données à partir du mot de passe
//! en chaînant des SHA-256. Simple, rapide, non-sécurisé (usage éducatif).

use crate::error::{Result, SteganoError};
use crate::traits::CryptoMethod;
use sha2::{Digest, Sha256};

pub struct Caesar;

impl Caesar {
    pub fn new() -> Self {
        Self
    }

    /// Dérive une clé de `length` bytes depuis le password (SHA-256 chaîné).
    /// Port exact du Python : `while len(key) < length: key += sha256(key).digest()`
    fn derive_key(password: &str, length: usize) -> Vec<u8> {
        let mut key = password.as_bytes().to_vec();
        while key.len() < length {
            let hash = Sha256::digest(&key);
            key.extend_from_slice(&hash);
        }
        key.truncate(length);
        key
    }
}

impl CryptoMethod for Caesar {
    fn id(&self) -> &str {
        "caesar"
    }

    fn name(&self) -> &str {
        "Caesar (XOR substitution)"
    }

    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
        if password.is_empty() {
            return Err(SteganoError::InvalidInput("password cannot be empty".into()));
        }
        let key = Self::derive_key(password, plaintext.len());
        Ok(plaintext
            .iter()
            .zip(key.iter())
            .map(|(p, k)| p ^ k)
            .collect())
    }

    fn decrypt(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
        // XOR is symmetric
        self.encrypt(ciphertext, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let c = Caesar::new();
        let plaintext = b"Hello SteganoHero!";
        let password = "secret";
        let encrypted = c.encrypt(plaintext, password).unwrap();
        let decrypted = c.decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_gives_garbage() {
        let c = Caesar::new();
        let encrypted = c.encrypt(b"secret", "right").unwrap();
        let decrypted = c.decrypt(&encrypted, "wrong").unwrap();
        assert_ne!(decrypted, b"secret");
    }

    #[test]
    fn empty_password_rejected() {
        let c = Caesar::new();
        assert!(c.encrypt(b"data", "").is_err());
    }

    #[test]
    fn long_data() {
        let c = Caesar::new();
        let data = vec![42u8; 1000];
        let encrypted = c.encrypt(&data, "pw").unwrap();
        let decrypted = c.decrypt(&encrypted, "pw").unwrap();
        assert_eq!(decrypted, data);
    }
}
