pub mod aes;
pub mod chacha;
pub mod caesar;
pub mod keytree;
pub mod xor;
pub mod pqc;

pub use aes::{Aes128, Aes256};
pub use keytree::KeyTree;
pub use chacha::ChaCha20;
pub use caesar::Caesar;
pub use xor::Xor;

use crate::error::{Result, SteganoError};
use crate::traits::KeyedCryptoMethod;

/// Recovery sweep over candidate ciphers — SPEC_CORE_V2 §6.3.
///
/// The key tree is derived once, per document; every candidate is then a plain
/// AEAD trial against the same `k_enc`. Returns the id of the cipher whose
/// authentication tag verified, with its plaintext.
///
/// Fails naming every candidate it tried. It never returns the input unchanged
/// and never reports a guess as a success.
pub fn decrypt_with_candidates(
    ciphertext: &[u8],
    candidates: &[&dyn KeyedCryptoMethod],
    keys: &KeyTree,
) -> Result<(String, Vec<u8>)> {
    if candidates.is_empty() {
        return Err(SteganoError::InvalidInput(
            "recovery sweep requires at least one candidate cipher".into(),
        ));
    }

    let mut tried: Vec<&str> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let key_len = candidate.key_len();
        if key_len > keys.k_enc().len() {
            return Err(SteganoError::DecodingFailed {
                method: candidate.id().to_string(),
                reason: format!(
                    "candidate needs a {key_len}-byte key, key tree provides {}",
                    keys.k_enc().len()
                ),
            });
        }

        if let Ok(plaintext) = candidate.decrypt_with_key(ciphertext, &keys.k_enc()[..key_len]) {
            return Ok((candidate.id().to_string(), plaintext));
        }
        tried.push(candidate.id());
    }

    Err(SteganoError::DecodingFailed {
        method: "recovery_sweep".into(),
        reason: format!(
            "no candidate cipher authenticated the payload: tried {}",
            tried.join(", ")
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keytree::argon2_derivation_count;
    use crate::traits::CryptoMethod;
    use std::time::Instant;

    /// F1 done-criterion: one Argon2 derivation across a multi-candidate sweep,
    /// where the password-taking path pays one derivation per attempt.
    #[test]
    fn recovery_sweep_derives_key_once() {
        let passcode = "one derivation per document";
        let aes256 = Aes256::new();
        let aes128 = Aes128::new();
        let chacha = ChaCha20::new();

        // Password path: three decrypt attempts, three Argon2 derivations.
        let legacy = chacha.encrypt(b"payload", passcode).unwrap();
        let before = argon2_derivation_count();
        for _ in 0..3 {
            chacha.decrypt(&legacy, passcode).unwrap();
        }
        assert_eq!(
            argon2_derivation_count() - before,
            3,
            "the v1 path derives once per decrypt attempt"
        );

        // Keyed path: one derivation, then three candidate trials.
        let before = argon2_derivation_count();
        let derive_start = Instant::now();
        let keys = KeyTree::generate(passcode).unwrap();
        let derive_elapsed = derive_start.elapsed();

        let ciphertext = chacha.encrypt_with_key(b"payload", keys.k_enc()).unwrap();
        let candidates: [&dyn KeyedCryptoMethod; 3] = [&aes256, &aes128, &chacha];

        let sweep_start = Instant::now();
        let (id, plaintext) = decrypt_with_candidates(&ciphertext, &candidates, &keys).unwrap();
        let sweep_elapsed = sweep_start.elapsed();

        assert_eq!(argon2_derivation_count() - before, 1);
        assert_eq!(id, "chacha20_poly1305");
        assert_eq!(plaintext, b"payload");
        assert!(
            sweep_elapsed < derive_elapsed,
            "sweeping {} candidates took {sweep_elapsed:?}, one derivation took {derive_elapsed:?}",
            candidates.len()
        );
    }

    #[test]
    fn recovery_sweep_names_every_candidate_it_tried() {
        let keys = KeyTree::derive("sweep failure names itself", &[2u8; 16]).unwrap();
        let aes256 = Aes256::new();
        let chacha = ChaCha20::new();
        let candidates: [&dyn KeyedCryptoMethod; 2] = [&aes256, &chacha];

        let result = decrypt_with_candidates(b"not a ciphertext at all", &candidates, &keys);

        match result {
            Err(SteganoError::DecodingFailed { method, reason }) => {
                assert_eq!(method, "recovery_sweep");
                assert!(reason.contains("aes256_gcm"), "reason was: {reason}");
                assert!(reason.contains("chacha20_poly1305"), "reason was: {reason}");
            }
            other => panic!("expected a named sweep failure, got {other:?}"),
        }
    }

    #[test]
    fn recovery_sweep_rejects_an_empty_candidate_list() {
        let keys = KeyTree::derive("no candidates", &[3u8; 16]).unwrap();
        let result = decrypt_with_candidates(b"anything", &[], &keys);
        assert!(matches!(result, Err(SteganoError::InvalidInput(_))));
    }
}
