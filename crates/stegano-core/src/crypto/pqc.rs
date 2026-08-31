//! Post-quantum recipient encryption: hybrid ML-KEM-768 + AES-256-GCM (KEM-DEM).
//!
//! A recipient holds an ML-KEM-768 keypair (FIPS 203). A sender seals a secret TO
//! the recipient's PUBLIC key: ML-KEM encapsulates a fresh 32-byte shared secret,
//! which keys an AES-256-GCM encryption of the payload. Only the recipient's
//! SECRET key recovers the shared secret and opens it.
//!
//! ML-KEM resists a quantum adversary (its security rests on the module-lattice
//! problem, not on factoring or discrete logs), and the AES-256-GCM layer keeps
//! the classical strength and authenticates the ciphertext, so any tampering is
//! detected rather than silently accepted. Pure Rust, offline: the secret never
//! travels, only its ciphertext, and there is no password to phish or brute-force
//! because the key is carried by the recipient's keypair.
//!
//! Wire format of a sealed payload:
//! `KEM ciphertext (1088 bytes) || AES-GCM nonce (12) || AES-GCM ciphertext+tag`.

use crate::error::{Result, SteganoError};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Key, Nonce,
};
use ml_kem::{
    Decapsulate, Encapsulate, Kem, KeyExport, KeyInit as MlKemKeyInit, MlKem768, TryKeyInit,
};

type Ek = <MlKem768 as Kem>::EncapsulationKey;
type Dk = <MlKem768 as Kem>::DecapsulationKey;

/// ML-KEM-768 ciphertext length in bytes (FIPS 203).
const KEM_CT_LEN: usize = 1088;
/// AES-256-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// A recipient's ML-KEM-768 keypair, encoded as bytes.
pub struct PqcKeypair {
    /// The public (encapsulation) key. Hand this to senders; it need not be secret.
    pub public: Vec<u8>,
    /// The secret (decapsulation) key. Keep this private; it opens sealed payloads.
    pub secret: Vec<u8>,
}

/// Generate a fresh ML-KEM-768 recipient keypair.
pub fn generate_keypair() -> PqcKeypair {
    let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
    PqcKeypair {
        public: ek.to_bytes().as_slice().to_vec(),
        secret: dk.to_bytes().as_slice().to_vec(),
    }
}

/// Seal `plaintext` to a recipient's public key. See the module doc for the wire
/// format. A malformed public key is refused by name (invariant 2).
pub fn seal(recipient_public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ek = <Ek as TryKeyInit>::new_from_slice(recipient_public)
        .map_err(|_| SteganoError::InvalidInput("malformed ML-KEM public key".into()))?;
    let (kem_ct, shared) = ek.encapsulate();

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(shared.as_slice()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let aes_ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SteganoError::EncryptionFailed("AES-256-GCM sealing failed".into()))?;

    let mut out = Vec::with_capacity(KEM_CT_LEN + NONCE_LEN + aes_ct.len());
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&aes_ct);
    Ok(out)
}

/// Open a sealed payload with the recipient's secret key. A wrong key, a truncated
/// payload, or any tampering is refused by name, never a silent partial (invariant
/// 2): the AES-256-GCM tag must verify.
pub fn open(recipient_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < KEM_CT_LEN + NONCE_LEN {
        return Err(SteganoError::InvalidInput(
            "sealed payload is too short to contain a ML-KEM ciphertext and a nonce".into(),
        ));
    }
    let dk = <Dk as MlKemKeyInit>::new_from_slice(recipient_secret)
        .map_err(|_| SteganoError::InvalidInput("malformed ML-KEM secret key".into()))?;
    let (kem_ct_bytes, rest) = sealed.split_at(KEM_CT_LEN);
    let (nonce_bytes, aes_ct) = rest.split_at(NONCE_LEN);

    // ML-KEM decapsulation is infallible: a wrong key yields a different shared
    // secret (implicit rejection), so the mismatch surfaces at the AES-256-GCM tag
    // below rather than here. A ciphertext of the wrong length is refused by name.
    let shared = dk
        .decapsulate_slice(kem_ct_bytes)
        .map_err(|_| SteganoError::InvalidInput("malformed ML-KEM ciphertext".into()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(shared.as_slice()));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), aes_ct)
        .map_err(|_| SteganoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_round_trip() {
        let kp = generate_keypair();
        let secret = b"the meeting is at dawn, bring the documents";
        let sealed = seal(&kp.public, secret).expect("seal to a valid public key");
        assert_ne!(sealed.as_slice(), secret, "the sealed payload is not the plaintext");
        let opened = open(&kp.secret, &sealed).expect("open with the matching secret key");
        assert_eq!(opened, secret, "the recipient recovers the exact secret");
    }

    #[test]
    fn a_wrong_secret_key_cannot_open() {
        let recipient = generate_keypair();
        let intruder = generate_keypair();
        let sealed = seal(&recipient.public, b"for the recipient only").unwrap();
        // ML-KEM decapsulation with the wrong key yields a different shared secret,
        // so the AES-256-GCM tag fails: a named refusal, never a partial plaintext.
        assert!(matches!(
            open(&intruder.secret, &sealed),
            Err(SteganoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let kp = generate_keypair();
        let mut sealed = seal(&kp.public, b"unaltered").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            open(&kp.secret, &sealed),
            Err(SteganoError::DecryptionFailed)
        ));
    }

    #[test]
    fn a_malformed_public_key_is_refused_by_name() {
        let err = seal(b"not a real ML-KEM key", b"x").unwrap_err();
        assert!(matches!(err, SteganoError::InvalidInput(_)));
    }

    #[test]
    fn a_truncated_payload_is_refused_by_name() {
        let kp = generate_keypair();
        let err = open(&kp.secret, b"too short").unwrap_err();
        assert!(matches!(err, SteganoError::InvalidInput(_)));
    }
}
