//! Canary Trap — Unique fingerprint per recipient
//!
//! Generates N visually identical versions of a document, each containing
//! a unique invisible fingerprint. If a document leaks, extract the fingerprint
//! to identify which recipient leaked it.
//!
//! Uses homoglyph substitution (most resilient: survives copy/paste, PDF, NFC).
//! Each substitutable character position encodes 1 bit of fingerprint.
//! With ~40% of English chars substitutable, a 500-char text gives ~200 bits
//! = enough for 2^200 unique fingerprints (effectively infinite).

use sha2::{Digest, Sha256};

use crate::error::{Result, SteganoError};
use crate::stego::Homoglyph;
use crate::traits::StegoMethod;

/// A recipient and their assigned fingerprint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Recipient {
    /// Human-readable identifier (name, email, department...).
    pub id: String,
    /// The fingerprint bytes assigned to this recipient.
    pub fingerprint: Vec<u8>,
    /// SHA-256 hash of the fingerprint (for quick lookup without exposing raw fp).
    pub fingerprint_hash: String,
}

/// Result of a canary trap generation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CanaryBatch {
    /// The original clean text.
    pub original: String,
    /// One watermarked version per recipient.
    pub versions: Vec<CanaryVersion>,
    /// Number of fingerprint bits used.
    pub fingerprint_bits: usize,
    /// Maximum recipients this text can support (2^bits, capped at u64::MAX).
    pub max_recipients: u64,
}

/// A single watermarked version for one recipient.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CanaryVersion {
    pub recipient: Recipient,
    /// The watermarked text (visually identical to original).
    pub text: String,
}

/// Result of fingerprint extraction from a leaked document.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CanaryMatch {
    /// The matched recipient (if found).
    pub recipient: Option<Recipient>,
    /// The raw fingerprint extracted from the text.
    pub extracted_fingerprint: Vec<u8>,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
}

// ─── Generation ─────────────────────────────────────────────

/// Generate a canary trap: N watermarked versions of the same text,
/// each with a unique fingerprint for one recipient.
///
/// The fingerprint is derived from `SHA-256(recipient_id + salt)`,
/// ensuring deterministic but unique fingerprints per recipient per document.
pub fn generate_batch(
    text: &str,
    recipient_ids: &[&str],
    salt: &str,
) -> Result<CanaryBatch> {
    let hg = Homoglyph::new();
    let capacity = hg.capacity(text); // bits available

    if capacity == 0 {
        return Err(SteganoError::InvalidInput(
            "text has no substitutable characters for fingerprinting".into(),
        ));
    }

    // We use `capacity` bits for the fingerprint (1 bit per substitutable position)
    // Floor division: never exceed available capacity
    let fp_bytes = capacity / 8;
    let max_recipients = if capacity >= 64 { u64::MAX } else { 1u64 << capacity };

    let mut versions = Vec::with_capacity(recipient_ids.len());

    for &rid in recipient_ids {
        // Derive fingerprint: SHA-256(recipient_id + ":" + salt), truncated to fp_bytes
        let fp = derive_fingerprint(rid, salt, fp_bytes);
        let fp_hash = hex_encode(&Sha256::digest(&fp));

        // Encode fingerprint into text using homoglyph substitution
        let watermarked = hg.encode(text, &fp)?;

        versions.push(CanaryVersion {
            recipient: Recipient {
                id: rid.to_string(),
                fingerprint: fp.clone(),
                fingerprint_hash: fp_hash,
            },
            text: watermarked,
        });
    }

    Ok(CanaryBatch {
        original: text.to_string(),
        versions,
        fingerprint_bits: capacity,
        max_recipients,
    })
}

/// Generate a single watermarked version for one recipient.
pub fn generate_single(
    text: &str,
    recipient_id: &str,
    salt: &str,
) -> Result<CanaryVersion> {
    let batch = generate_batch(text, &[recipient_id], salt)?;
    Ok(batch.versions.into_iter().next().unwrap())
}

// ─── Extraction & Identification ────────────────────────────

/// Extract the fingerprint from a potentially leaked document
/// and try to match it against a list of known recipients.
pub fn identify_leak(
    leaked_text: &str,
    known_recipients: &[Recipient],
) -> Result<CanaryMatch> {
    let hg = Homoglyph::new();

    // Detect if there are homoglyph substitutions
    let detection = hg.detect(leaked_text);
    if detection < 0.01 {
        return Ok(CanaryMatch {
            recipient: None,
            extracted_fingerprint: vec![],
            confidence: 0.0,
        });
    }

    // Extract the raw fingerprint bytes
    let extracted = hg.decode(leaked_text)?;

    // Try to match against known recipients
    let extracted_hash = hex_encode(&Sha256::digest(&extracted));

    let matched = known_recipients
        .iter()
        .find(|r| r.fingerprint_hash == extracted_hash)
        .cloned();

    // Confidence: high if exact match, medium if homoglyphs detected but no match
    let confidence = if matched.is_some() {
        1.0
    } else if detection > 0.3 {
        0.5 // Has homoglyphs but no recipient match — partial leak or unknown recipient
    } else {
        detection
    };

    Ok(CanaryMatch {
        recipient: matched,
        extracted_fingerprint: extracted,
        confidence,
    })
}

/// Extract fingerprint from leaked text and compare against a single recipient.
/// Returns true if this text came from that recipient's version.
pub fn verify_recipient(
    leaked_text: &str,
    recipient_id: &str,
    salt: &str,
    fp_bytes: usize,
) -> Result<bool> {
    let hg = Homoglyph::new();
    let extracted = hg.decode(leaked_text)?;

    let expected = derive_fingerprint(recipient_id, salt, fp_bytes);

    // Compare only the available bytes (leaked text might be truncated)
    let compare_len = extracted.len().min(expected.len());
    if compare_len == 0 {
        return Ok(false);
    }

    Ok(extracted[..compare_len] == expected[..compare_len])
}

// ─── Helpers ────────────────────────────────────────────────

/// Derive a deterministic fingerprint from recipient ID + salt.
fn derive_fingerprint(recipient_id: &str, salt: &str, length: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(recipient_id.as_bytes());
    hasher.update(b":");
    hasher.update(salt.as_bytes());
    let hash = hasher.finalize();

    // If we need more bytes than SHA-256 provides (32), chain hashes
    if length <= 32 {
        hash[..length].to_vec()
    } else {
        let mut result = hash.to_vec();
        let mut counter = 1u32;
        while result.len() < length {
            let mut h = Sha256::new();
            h.update(&hash);
            h.update(&counter.to_le_bytes());
            result.extend_from_slice(&h.finalize());
            counter += 1;
        }
        result.truncate(length);
        result
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TEXT: &str = "\
        Access to the open science project expectations are exceptional in scope \
        and practice today across every possible aspect of the ecosystem operations \
        including all cooperative joint exercises previously associated with the \
        core operations executive committee since its inception a year ago today";

    #[test]
    fn generate_batch_produces_unique_versions() {
        let batch = generate_batch(
            SAMPLE_TEXT,
            &["alice@company.ch", "bob@company.ch", "carol@company.ch"],
            "doc-2026-q1",
        )
        .unwrap();

        assert_eq!(batch.versions.len(), 3);

        // Each version should be different
        let texts: Vec<&str> = batch.versions.iter().map(|v| v.text.as_str()).collect();
        assert_ne!(texts[0], texts[1]);
        assert_ne!(texts[1], texts[2]);
        assert_ne!(texts[0], texts[2]);

        // But they should all LOOK the same when stripped
        let hg = Homoglyph::new();
        for v in &batch.versions {
            assert_eq!(hg.strip(&v.text), SAMPLE_TEXT);
        }
    }

    #[test]
    fn fingerprints_are_unique_per_recipient() {
        let batch = generate_batch(
            SAMPLE_TEXT,
            &["alice", "bob"],
            "salt",
        )
        .unwrap();

        let fp_a = &batch.versions[0].recipient.fingerprint;
        let fp_b = &batch.versions[1].recipient.fingerprint;
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn fingerprints_are_deterministic() {
        let batch1 = generate_batch(SAMPLE_TEXT, &["alice"], "salt").unwrap();
        let batch2 = generate_batch(SAMPLE_TEXT, &["alice"], "salt").unwrap();

        // Same recipient + same salt = same fingerprint
        assert_eq!(
            batch1.versions[0].recipient.fingerprint,
            batch2.versions[0].recipient.fingerprint
        );
        assert_eq!(batch1.versions[0].text, batch2.versions[0].text);
    }

    #[test]
    fn different_salt_different_fingerprint() {
        let batch1 = generate_batch(SAMPLE_TEXT, &["alice"], "salt-1").unwrap();
        let batch2 = generate_batch(SAMPLE_TEXT, &["alice"], "salt-2").unwrap();

        assert_ne!(
            batch1.versions[0].recipient.fingerprint,
            batch2.versions[0].recipient.fingerprint
        );
    }

    #[test]
    fn identify_leak_finds_recipient() {
        let batch = generate_batch(
            SAMPLE_TEXT,
            &["alice", "bob", "carol"],
            "secret-salt",
        )
        .unwrap();

        // Simulate: Bob's version leaks
        let leaked = &batch.versions[1].text;
        let recipients: Vec<Recipient> = batch.versions.iter().map(|v| v.recipient.clone()).collect();

        let result = identify_leak(leaked, &recipients).unwrap();

        assert!(result.recipient.is_some());
        assert_eq!(result.recipient.unwrap().id, "bob");
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn identify_leak_clean_text_no_match() {
        let result = identify_leak(SAMPLE_TEXT, &[]).unwrap();

        assert!(result.recipient.is_none());
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn verify_recipient_positive() {
        let version = generate_single(SAMPLE_TEXT, "alice", "salt").unwrap();
        let hg = Homoglyph::new();
        let fp_bytes = (hg.capacity(SAMPLE_TEXT) + 7) / 8;

        assert!(verify_recipient(&version.text, "alice", "salt", fp_bytes).unwrap());
        assert!(!verify_recipient(&version.text, "bob", "salt", fp_bytes).unwrap());
    }

    #[test]
    fn capacity_report() {
        let batch = generate_batch(SAMPLE_TEXT, &["test"], "s").unwrap();

        println!("Text length: {} chars", SAMPLE_TEXT.len());
        println!("Fingerprint bits: {}", batch.fingerprint_bits);
        println!("Max unique recipients: {}", batch.max_recipients);

        // English text should have good capacity
        assert!(batch.fingerprint_bits > 50, "Expected >50 bits, got {}", batch.fingerprint_bits);
    }

    #[test]
    fn batch_with_many_recipients() {
        // Generate 50 unique versions — like a real canary trap
        let recipients: Vec<String> = (0..50).map(|i| format!("employee_{i:03}")).collect();
        let recipient_refs: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();

        let batch = generate_batch(SAMPLE_TEXT, &recipient_refs, "quarterly-report-2026-q2").unwrap();

        assert_eq!(batch.versions.len(), 50);

        // All versions should be unique
        let mut texts: Vec<String> = batch.versions.iter().map(|v| v.text.clone()).collect();
        texts.sort();
        texts.dedup();
        assert_eq!(texts.len(), 50, "All 50 versions should be unique");

        // Verify each can be identified
        let all_recipients: Vec<Recipient> = batch.versions.iter().map(|v| v.recipient.clone()).collect();
        for v in &batch.versions {
            let m = identify_leak(&v.text, &all_recipients).unwrap();
            assert_eq!(m.recipient.unwrap().id, v.recipient.id);
        }
    }
}
