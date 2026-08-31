//! XOR cipher — port fidèle du plugin Python SteganoHero-v1.
//!
//! Identique au Caesar (les deux sont des XOR dans le Python original).
//! Gardé comme méthode séparée pour compatibilité.

use crate::error::{Result, SteganoError};
use crate::traits::CryptoMethod;
use sha2::{Digest, Sha256};

pub struct Xor;

impl Xor {
    pub fn new() -> Self {
        Self
    }

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

impl CryptoMethod for Xor {
    fn id(&self) -> &str {
        "xor"
    }

    fn name(&self) -> &str {
        "XOR"
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
        self.encrypt(ciphertext, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let x = Xor::new();
        let plaintext = b"XOR encryption test";
        let password = "mypassword";
        let encrypted = x.encrypt(plaintext, password).unwrap();
        let decrypted = x.decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn symmetric() {
        let x = Xor::new();
        let data = b"symmetric";
        let pw = "key";
        let enc = x.encrypt(data, pw).unwrap();
        let dec = x.encrypt(&enc, pw).unwrap(); // encrypt again = decrypt
        assert_eq!(dec, data);
    }
}
