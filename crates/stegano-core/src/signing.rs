//! Ed25519 digital signatures for license authentication.
//!
//! The signing key (private) stays with the admin.
//! The verifying key (public) is embedded in every distributed binary.
//! This means anyone can VERIFY a license, but only the admin can CREATE one.

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;

use crate::error::{Result, SteganoError};

/// Admin-side key pair for signing licenses.
pub struct MasterKeyPair {
    signing: SigningKey,
}

impl MasterKeyPair {
    /// Generate a new random key pair. Save the private key securely!
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Import from raw private key bytes (32 bytes).
    pub fn from_private_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// Export raw private key bytes. KEEP SECRET.
    pub fn private_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing.to_bytes()
    }

    /// Export the public verifying key.
    pub fn public_key(&self) -> MasterPublicKey {
        MasterPublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Sign arbitrary data. Returns 64-byte Ed25519 signature.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(data);
        sig.to_bytes().to_vec()
    }
}

/// Public key for verifying license signatures.
/// Embedded in the distributed binary — this is NOT secret.
#[derive(Clone)]
pub struct MasterPublicKey {
    verifying: VerifyingKey,
}

impl MasterPublicKey {
    /// Import from raw public key bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self> {
        let verifying = VerifyingKey::from_bytes(bytes)
            .map_err(|e| SteganoError::InvalidLicense(format!("invalid public key: {e}")))?;
        Ok(Self { verifying })
    }

    /// Export raw public key bytes (32 bytes). Safe to distribute.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.verifying.to_bytes()
    }

    /// Verify a signature against data. Returns Ok(()) or Err.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(SteganoError::InvalidLicense(format!(
                "signature must be {} bytes, got {}",
                SIGNATURE_LENGTH,
                signature.len()
            )));
        }

        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature.try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        self.verifying
            .verify(data, &sig)
            .map_err(|_| SteganoError::InvalidLicense("signature verification failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let keypair = MasterKeyPair::generate();
        let pubkey = keypair.public_key();

        let data = b"license payload here";
        let sig = keypair.sign(data);

        assert!(pubkey.verify(data, &sig).is_ok());
    }

    #[test]
    fn tampered_data_fails() {
        let keypair = MasterKeyPair::generate();
        let pubkey = keypair.public_key();

        let sig = keypair.sign(b"original");
        assert!(pubkey.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let keypair = MasterKeyPair::generate();
        let pubkey = keypair.public_key();

        let mut sig = keypair.sign(b"data");
        sig[0] ^= 0xFF; // flip bits

        assert!(pubkey.verify(b"data", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let keypair1 = MasterKeyPair::generate();
        let keypair2 = MasterKeyPair::generate();

        let sig = keypair1.sign(b"data");
        assert!(keypair2.public_key().verify(b"data", &sig).is_err());
    }

    #[test]
    fn export_import_roundtrip() {
        let keypair = MasterKeyPair::generate();
        let private_bytes = keypair.private_bytes();
        let public_bytes = keypair.public_key().to_bytes();

        let restored = MasterKeyPair::from_private_bytes(&private_bytes);
        let restored_pub = MasterPublicKey::from_bytes(&public_bytes).unwrap();

        let sig = restored.sign(b"test");
        assert!(restored_pub.verify(b"test", &sig).is_ok());
    }
}
