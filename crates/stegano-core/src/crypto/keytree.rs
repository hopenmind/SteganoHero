//! Unified key tree — SPEC_CORE_V2 §2.
//!
//! One Argon2id derivation per document, then HKDF-SHA256 domain separation:
//!
//! ```text
//! master  = Argon2id(passcode, salt, m = 65536 KiB, t = 3, p = 1) -> 32 bytes
//! k_enc   = HKDF-SHA256(master, "stegano/v2/enc")    -> 32 bytes
//! k_place = HKDF-SHA256(master, "stegano/v2/place")  -> 32 bytes
//! k_hdr   = HKDF-SHA256(master, "stegano/v2/header") -> 16 bytes
//! ```
//!
//! Why this exists: each cipher used to generate its own salt and run its own
//! Argon2 (`aes.rs`, `chacha.rs`). A recovery sweep therefore paid one
//! derivation per candidate instead of one per document. Those password-taking
//! paths stay in place for v1 ciphertexts; new work derives here and hands the
//! ciphers a key through `KeyedCryptoMethod`.
//!
//! HMAC-SHA256 and HKDF-SHA256 are implemented on top of `sha2` rather than
//! pulled in as new dependencies, and are pinned to the RFC 4231 / RFC 5869
//! test vectors below.

use std::cell::Cell;

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

use crate::error::{Result, SteganoError};

// ─── Parameters (SPEC_CORE_V2 §2) ───

/// Argon2id memory cost, in KiB.
pub const ARGON2_MEMORY_KIB: u32 = 65536;
/// Argon2id time cost (passes).
pub const ARGON2_TIME_COST: u32 = 3;
/// Argon2id parallelism (lanes).
pub const ARGON2_PARALLELISM: u32 = 1;

/// Document salt length, in bytes.
pub const SALT_LEN: usize = 16;
/// Master key length, in bytes.
pub const MASTER_LEN: usize = 32;
/// AEAD key length, in bytes.
pub const K_ENC_LEN: usize = 32;
/// Placement seed length, in bytes.
pub const K_PLACE_LEN: usize = 32;
/// Stealth header key length, in bytes.
pub const K_HDR_LEN: usize = 16;

const INFO_ENC: &[u8] = b"stegano/v2/enc";
const INFO_PLACE: &[u8] = b"stegano/v2/place";
const INFO_HDR: &[u8] = b"stegano/v2/header";

const HASH_LEN: usize = 32;
const HMAC_BLOCK_LEN: usize = 64;

thread_local! {
    static ARGON2_DERIVATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Number of Argon2 derivations performed on the current thread.
///
/// Instrumentation for the recovery-cost criterion (SPEC_CORE_V2 §6.3): a
/// multi-candidate sweep must cost one derivation per document, never one per
/// candidate. Counted per thread so a test observes only its own work.
pub fn argon2_derivation_count() -> u64 {
    ARGON2_DERIVATIONS.with(|c| c.get())
}

/// Record one Argon2 derivation. Called by every path that runs Argon2,
/// including the v1 password-taking cipher paths.
pub(crate) fn note_argon2_derivation() {
    ARGON2_DERIVATIONS.with(|c| c.set(c.get() + 1));
}

// ─── Key tree ───

/// The per-document key material derived from a passcode and a salt.
#[derive(Clone)]
pub struct KeyTree {
    salt: [u8; SALT_LEN],
    k_enc: [u8; K_ENC_LEN],
    k_place: [u8; K_PLACE_LEN],
    k_hdr: [u8; K_HDR_LEN],
}

impl KeyTree {
    /// Derive the tree from `passcode` and an existing document `salt`.
    ///
    /// Runs exactly one Argon2id derivation. Everything below it is HKDF.
    pub fn derive(passcode: &str, salt: &[u8; SALT_LEN]) -> Result<Self> {
        if passcode.is_empty() {
            return Err(SteganoError::InvalidInput(
                "keytree: passcode cannot be empty".into(),
            ));
        }

        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(MASTER_LEN),
        )
        .map_err(|e| {
            SteganoError::EncryptionFailed(format!("keytree: invalid Argon2 parameters: {e}"))
        })?;

        let mut master = [0u8; MASTER_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passcode.as_bytes(), salt, &mut master)
            .map_err(|e| {
                SteganoError::EncryptionFailed(format!("keytree: master derivation failed: {e}"))
            })?;
        note_argon2_derivation();

        let mut k_enc = [0u8; K_ENC_LEN];
        let mut k_place = [0u8; K_PLACE_LEN];
        let mut k_hdr = [0u8; K_HDR_LEN];
        hkdf_sha256(&master, &[], INFO_ENC, &mut k_enc)?;
        hkdf_sha256(&master, &[], INFO_PLACE, &mut k_place)?;
        hkdf_sha256(&master, &[], INFO_HDR, &mut k_hdr)?;

        Ok(Self {
            salt: *salt,
            k_enc,
            k_place,
            k_hdr,
        })
    }

    /// Derive the tree from `passcode` under a fresh random document salt.
    pub fn generate(passcode: &str) -> Result<Self> {
        let salt: [u8; SALT_LEN] = rand::random();
        Self::derive(passcode, &salt)
    }

    /// The document salt this tree was derived under.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// AEAD key. Ciphers with shorter keys take the leading bytes.
    pub fn k_enc(&self) -> &[u8; K_ENC_LEN] {
        &self.k_enc
    }

    /// Payload placement seed.
    pub fn k_place(&self) -> &[u8; K_PLACE_LEN] {
        &self.k_place
    }

    /// Stealth marker derivation key.
    pub fn k_hdr(&self) -> &[u8; K_HDR_LEN] {
        &self.k_hdr
    }
}

// ─── HMAC-SHA256 / HKDF-SHA256 ───

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let mut block_key = [0u8; HMAC_BLOCK_LEN];
    if key.len() > HMAC_BLOCK_LEN {
        block_key[..HASH_LEN].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_LEN];
    let mut opad = [0x5cu8; HMAC_BLOCK_LEN];
    for i in 0..HMAC_BLOCK_LEN {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);

    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&outer.finalize());
    out
}

/// HKDF-SHA256 extract-then-expand (RFC 5869), filling `okm`.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    if okm.is_empty() || okm.len() > 255 * HASH_LEN {
        return Err(SteganoError::InvalidInput(format!(
            "hkdf: output length {} outside 1..={}",
            okm.len(),
            255 * HASH_LEN
        )));
    }

    let prk = hmac_sha256(salt, ikm);

    let mut previous: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut counter: u8 = 1;
    while written < okm.len() {
        let mut block_input = Vec::with_capacity(previous.len() + info.len() + 1);
        block_input.extend_from_slice(&previous);
        block_input.extend_from_slice(info);
        block_input.push(counter);

        let block = hmac_sha256(&prk, &block_input);
        let take = (okm.len() - written).min(HASH_LEN);
        okm[written..written + take].copy_from_slice(&block[..take]);

        previous = block.to_vec();
        written += take;
        counter += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ─── Primitives pinned to their RFC vectors ───

    #[test]
    fn hmac_sha256_matches_rfc4231() {
        // Test case 1.
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            to_hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // Test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            to_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut okm).unwrap();
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc5869_case_3() {
        // Zero-length salt and info — the shape the key tree uses.
        let ikm = [0x0b; 22];
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &[], &[], &mut okm).unwrap();
        assert_eq!(
            to_hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_rejects_impossible_output_length() {
        let mut nothing: [u8; 0] = [];
        assert!(hkdf_sha256(b"ikm", &[], &[], &mut nothing).is_err());
    }

    // ─── Key tree ───

    #[test]
    fn parameters_match_spec() {
        assert_eq!(ARGON2_MEMORY_KIB, 65536);
        assert_eq!(ARGON2_TIME_COST, 3);
        assert_eq!(ARGON2_PARALLELISM, 1);
        assert_eq!(MASTER_LEN, 32);
        assert_eq!(K_ENC_LEN, 32);
        assert_eq!(K_PLACE_LEN, 32);
        assert_eq!(K_HDR_LEN, 16);
    }

    #[test]
    fn derivation_is_deterministic_and_salt_bound() {
        let salt = [7u8; SALT_LEN];
        let other_salt = [8u8; SALT_LEN];

        let a = KeyTree::derive("correct horse battery staple", &salt).unwrap();
        let b = KeyTree::derive("correct horse battery staple", &salt).unwrap();
        let c = KeyTree::derive("correct horse battery staple", &other_salt).unwrap();

        assert_eq!(a.k_enc(), b.k_enc());
        assert_eq!(a.k_place(), b.k_place());
        assert_eq!(a.k_hdr(), b.k_hdr());
        assert_eq!(a.salt(), &salt);

        assert_ne!(a.k_enc(), c.k_enc());
    }

    #[test]
    fn domains_are_separated() {
        let tree = KeyTree::derive("a passcode for domain separation", &[3u8; SALT_LEN]).unwrap();

        assert_ne!(tree.k_enc().as_slice(), tree.k_place().as_slice());
        assert_ne!(&tree.k_enc()[..K_HDR_LEN], tree.k_hdr().as_slice());
        assert_ne!(&tree.k_place()[..K_HDR_LEN], tree.k_hdr().as_slice());
    }

    #[test]
    fn one_argon2_call_per_tree() {
        let before = argon2_derivation_count();
        let _ = KeyTree::derive("counted once", &[1u8; SALT_LEN]).unwrap();
        assert_eq!(argon2_derivation_count() - before, 1);
    }

    #[test]
    fn empty_passcode_rejected() {
        let before = argon2_derivation_count();
        let result = KeyTree::derive("", &[0u8; SALT_LEN]);
        assert!(matches!(result, Err(SteganoError::InvalidInput(_))));
        assert_eq!(
            argon2_derivation_count() - before,
            0,
            "a rejected passcode must not pay for a derivation"
        );
    }

    #[test]
    fn generate_uses_a_fresh_salt() {
        let a = KeyTree::generate("same passcode, different documents").unwrap();
        let b = KeyTree::generate("same passcode, different documents").unwrap();
        assert_ne!(a.salt(), b.salt());
        assert_ne!(a.k_enc(), b.k_enc());
    }
}
