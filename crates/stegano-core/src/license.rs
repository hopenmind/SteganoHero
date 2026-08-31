//! Steganographic License System
//!
//! A license IS a normal-looking paragraph of text.
//! Inside, invisible to the eye, it contains:
//! - authorized modules
//! - licensee identity
//! - hardware binding (optional)
//! - expiry date (optional)
//! - operation counter (optional)
//! - canary fingerprint (for leak tracing)
//! - Ed25519 signature (tamper-proof)
//!
//! Validation is 100% offline. No network. No DRM server.
//! The public key is embedded in the binary. Only the admin has the private key.

use sha2::{Digest, Sha256};

use crate::error::{Result, SteganoError};
use crate::signing::{MasterKeyPair, MasterPublicKey};
use crate::stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth};
use crate::traits::StegoMethod;

// ─── License struct ─────────────────────────────────────────

/// A SteganoHero license — the core authorization unit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct License {
    /// Format version (for forward compatibility).
    pub v: u8,
    /// Unique license identifier.
    pub id: String,
    /// Who holds this license.
    pub licensee: String,
    /// Which modules are authorized.
    pub modules: Vec<String>,
    /// SHA-256 of machine fingerprint (None = not hardware-bound).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hw_hash: Option<String>,
    /// Domain pattern for site licenses (e.g., "*.company.ch").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// ISO 8601 timestamp when issued.
    pub issued: String,
    /// ISO 8601 timestamp when it expires (None = perpetual).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Max operations allowed (None = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ops: Option<u64>,
    /// Unique canary fingerprint for leak tracing (hex string).
    pub canary: String,
    /// SHA-256 of the document this claim was signed over, hex, taken after
    /// every carrier's `strip()` so it survives the embedding (SPEC_CORE_V2
    /// §6.4, backlog F12). `sign_and_embed` fills it; `extract_and_verify`
    /// recomputes it and refuses on mismatch.
    ///
    /// `None` marks a claim signed before document binding existed. Such a
    /// claim covers itself only, so verification refuses it by name rather
    /// than passing it off as proof about the surrounding text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_hash: Option<String>,
}

/// Builder for creating licenses (admin side).
pub struct LicenseBuilder {
    licensee: String,
    modules: Vec<String>,
    hw_hash: Option<String>,
    org: Option<String>,
    expires: Option<String>,
    max_ops: Option<u64>,
}

impl LicenseBuilder {
    pub fn new(licensee: &str) -> Self {
        Self {
            licensee: licensee.to_string(),
            modules: Vec::new(),
            hw_hash: None,
            org: None,
            expires: None,
            max_ops: None,
        }
    }

    /// Add an authorized module.
    pub fn module(mut self, module_id: &str) -> Self {
        self.modules.push(module_id.to_string());
        self
    }

    /// Add multiple modules at once.
    pub fn modules(mut self, modules: &[&str]) -> Self {
        self.modules.extend(modules.iter().map(|s| s.to_string()));
        self
    }

    /// Bind to a specific machine (hardware fingerprint hash).
    pub fn hardware(mut self, fingerprint: &str) -> Self {
        self.hw_hash = Some(hash_fingerprint(fingerprint));
        self
    }

    /// Bind to an organization domain pattern.
    pub fn org(mut self, pattern: &str) -> Self {
        self.org = Some(pattern.to_string());
        self
    }

    /// Set expiry date (ISO 8601 format, e.g., "2027-01-01T00:00:00Z").
    pub fn expires(mut self, date: &str) -> Self {
        self.expires = Some(date.to_string());
        self
    }

    /// Set maximum number of operations.
    pub fn max_ops(mut self, n: u64) -> Self {
        self.max_ops = Some(n);
        self
    }

    /// Build the license. Generates unique ID and canary automatically.
    pub fn build(self) -> License {
        let id = format!("lic_{}", &random_hex(8));
        let canary = random_hex(8);
        let issued = now_iso8601();

        License {
            v: 1,
            id,
            licensee: self.licensee,
            modules: self.modules,
            hw_hash: self.hw_hash,
            org: self.org,
            issued,
            expires: self.expires,
            max_ops: self.max_ops,
            canary,
            // Bound to a document by `sign_and_embed`, which is the only place
            // that knows which document the claim is being attached to.
            doc_hash: None,
        }
    }
}

// ─── Signed license package ─────────────────────────────────

/// A signed license package: license JSON + Ed25519 signature.
/// This is what gets embedded in the stego text.
#[derive(serde::Serialize, serde::Deserialize)]
struct SignedPackage {
    /// License JSON (compact).
    lic: String,
    /// Ed25519 signature (hex-encoded, 128 hex chars = 64 bytes).
    sig: String,
}

// ─── Admin operations: sign and embed ───────────────────────

/// Sign a license and embed it steganographically into cover text.
///
/// Returns the stego text that looks like `cover` but contains the license.
/// This is the admin-side operation — requires the master private key.
///
/// The signature covers the document as well as the claim: `doc_hash` is set
/// to `document_hash(cover)` before signing, so altering the visible text
/// afterwards is detectable (backlog F12). The caller's `license` is not
/// modified; the binding is applied to a copy.
pub fn sign_and_embed(
    license: &License,
    keypair: &MasterKeyPair,
    cover: &str,
    method: &dyn StegoMethod,
) -> Result<String> {
    // Bind the claim to the document before it is signed. Hashing the stripped
    // cover rather than the raw cover keeps the figure reproducible once the
    // claim itself has been embedded (SPEC_CORE_V2 §6.4).
    let mut bound = license.clone();
    bound.doc_hash = Some(document_hash(cover)?);

    // Serialize license to compact JSON
    let lic_json = serde_json::to_string(&bound)?;

    // Sign the JSON bytes
    let signature = keypair.sign(lic_json.as_bytes());
    let sig_hex = hex_encode(&signature);

    // Package: { lic: "...", sig: "..." }
    let package = SignedPackage {
        lic: lic_json,
        sig: sig_hex,
    };
    let package_json = serde_json::to_string(&package)?;

    // Refuse up front only when the cover bounds this carrier. A carrier that
    // overflows past the cover creates the positions it needs and is never held
    // to the raw figure: its `encode` cannot run out of room. `capacity()` is
    // the raw figure, one payload bit per position (backlog F25), which is a
    // hard ceiling only for a bounded carrier. For an overflow carrier `encode`
    // is the authority, and it names any refusal of its own.
    if crate::format::cover_bounds_writes(method, cover) {
        let needed = package_json.len() * 8;
        let available = method.capacity(cover);
        if needed > available {
            return Err(SteganoError::CapacityExceeded { needed, available });
        }
    }

    // Embed via steganography
    method.encode(cover, package_json.as_bytes())
}

// ─── Client operations: extract and verify ──────────────────

/// Extract a license from stego text and verify its signature, then confirm
/// the claim is the one made about *this* document.
///
/// Returns the validated license. This is the client-side operation —
/// only requires the public key (embedded in the binary).
///
/// Two things are checked, and a failure names which one gave way: the
/// Ed25519 signature over the claim, then the document hash the claim carries
/// against the document it was found in (backlog F12).
pub fn extract_and_verify(
    stego_text: &str,
    public_key: &MasterPublicKey,
    method: &dyn StegoMethod,
) -> Result<License> {
    // Extract hidden data
    let raw_bytes = method.decode(stego_text)?;

    // Parse package
    let package_json =
        String::from_utf8(raw_bytes).map_err(|_| SteganoError::InvalidLicense("corrupt data".into()))?;

    let package: SignedPackage = serde_json::from_str(&package_json)
        .map_err(|_| SteganoError::InvalidLicense("invalid package format".into()))?;

    // Decode signature from hex
    let sig_bytes =
        hex_decode(&package.sig).map_err(|_| SteganoError::InvalidLicense("invalid signature hex".into()))?;

    // Verify signature against license JSON
    public_key.verify(package.lic.as_bytes(), &sig_bytes)?;

    // Parse the license
    let license: License = serde_json::from_str(&package.lic)
        .map_err(|e| SteganoError::InvalidLicense(format!("invalid license JSON: {e}")))?;

    // The signature proves the claim was not altered. It says nothing about
    // the document unless the claim carries the document's hash, so check that
    // second and name it separately.
    match &license.doc_hash {
        None => {
            return Err(SteganoError::InvalidLicense(
                "claim format difference: this claim carries no document hash, so it was \
                 signed before document binding existed and proves nothing about the text \
                 around it; the signature itself is intact, re-sign the document with the \
                 current version to bind them"
                    .into(),
            ));
        }
        Some(claimed) => {
            let actual = document_hash(stego_text)?;
            if &actual != claimed {
                return Err(SteganoError::InvalidLicense(format!(
                    "document hash mismatch: the claim was signed over the document \
                     {claimed}, this document strips to {actual}; the visible text has \
                     been altered since the claim was attached"
                )));
            }
        }
    }

    Ok(license)
}

// ─── Document binding ───────────────────────────────────────

/// SHA-256 of a document as it reads once every carrier's artifacts are gone,
/// hex-encoded. This is what a claim is bound to (SPEC_CORE_V2 §6.4).
///
/// Stripping before hashing is what makes the figure reproducible: the cover
/// and the same cover carrying an embedded claim strip to the same text, so
/// the signer and the verifier compute the same hash.
pub fn document_hash(text: &str) -> Result<String> {
    let stripped = strip_all(text)?;
    Ok(hex_encode(&Sha256::digest(stripped.as_bytes())))
}

/// Apply every registered carrier's `strip()` in canonical id order:
/// `bidi`, `homoglyph`, `whitespace_var`, `zero_width`.
///
/// Every carrier's `strip()` is now attribution-based and non-destructive: it
/// reverts only the characters it can show are its own work and leaves the rest
/// byte for byte. `Homoglyph::strip()` in particular restores only the Cyrillic
/// lookalikes it attributes as substitutions and leaves legitimate Cyrillic
/// prose untouched (backlog F7). A document that carries an authorship claim
/// over the homoglyph channel is, by definition, one that contains substitutes,
/// so hashing it is the intended path rather than one to refuse (backlog F12b):
/// the marked document strips back to the cover and hashes to the same figure.
fn strip_all(text: &str) -> Result<String> {
    let bidi = Bidi::new();
    let homoglyph = Homoglyph::new();
    let whitespace = WhitespaceVar::new();
    let zero_width = ZeroWidth::new();

    let carriers: [&dyn StegoMethod; 4] = [&bidi, &homoglyph, &whitespace, &zero_width];
    let mut stripped = text.to_string();
    for carrier in carriers {
        stripped = carrier.strip(&stripped);
    }
    Ok(stripped)
}

// ─── License validation ─────────────────────────────────────

impl License {
    /// Check if a specific module is authorized by this license.
    pub fn check_module(&self, module_id: &str) -> Result<()> {
        // Wildcard "*" means all modules
        if self.modules.iter().any(|m| m == "*" || m == module_id) {
            Ok(())
        } else {
            Err(SteganoError::ModuleNotLicensed {
                module: module_id.to_string(),
            })
        }
    }

    /// Check if the license has expired. Pass current date as ISO 8601.
    pub fn check_expiry(&self, now_iso: &str) -> Result<()> {
        match &self.expires {
            None => Ok(()), // Perpetual license
            Some(expiry) => {
                // Simple lexicographic comparison works for ISO 8601
                if now_iso <= expiry.as_str() {
                    Ok(())
                } else {
                    Err(SteganoError::LicenseExpired)
                }
            }
        }
    }

    /// Check if the hardware matches. Pass the raw machine fingerprint
    /// (same value used during license creation).
    pub fn check_hardware(&self, fingerprint: &str) -> Result<()> {
        match &self.hw_hash {
            None => Ok(()), // Not hardware-bound
            Some(expected) => {
                let actual = hash_fingerprint(fingerprint);
                if actual == *expected {
                    Ok(())
                } else {
                    Err(SteganoError::InvalidLicense(
                        "hardware mismatch: this license is bound to a different machine".into(),
                    ))
                }
            }
        }
    }

    /// Check if the hostname matches the org domain pattern.
    pub fn check_org(&self, hostname: &str) -> Result<()> {
        match &self.org {
            None => Ok(()), // Not org-bound
            Some(pattern) => {
                if matches_domain(hostname, pattern) {
                    Ok(())
                } else {
                    Err(SteganoError::InvalidLicense(format!(
                        "hostname '{hostname}' does not match org pattern '{pattern}'"
                    )))
                }
            }
        }
    }
}

// ─── Hardware fingerprint ───────────────────────────────────

/// Collect the machine fingerprint. Cross-platform.
/// Returns a string like "hostname:machine_id" that uniquely identifies this machine.
pub fn machine_fingerprint() -> String {
    let hostname = get_hostname();
    let machine_id = get_machine_id();
    format!("{hostname}:{machine_id}")
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(target_os = "windows")]
fn get_machine_id() -> String {
    // Read MachineGuid from Windows registry
    std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.contains("MachineGuid"))
                .and_then(|l| l.split_whitespace().last().map(|v| v.to_string()))
        })
        .unwrap_or_else(|| "no-machine-id".to_string())
}

#[cfg(target_os = "linux")]
fn get_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_else(|_| "no-machine-id".to_string())
        .trim()
        .to_string()
}

#[cfg(target_os = "macos")]
fn get_machine_id() -> String {
    std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.contains("IOPlatformUUID"))
                .and_then(|l| l.split('"').nth(3).map(|v| v.to_string()))
        })
        .unwrap_or_else(|| "no-machine-id".to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_machine_id() -> String {
    "unsupported-platform".to_string()
}

// ─── Default cover text for licenses ────────────────────────

/// Returns a default legal-sounding cover text with enough capacity
/// for embedding a license via zero-width steganography (~600 chars = ~4800 bits).
pub fn default_license_cover() -> &'static str {
    "This document certifies the authorized use of SteganoHero software modules \
     under the terms agreed upon between the licensee and Hope n Mind the developer \
     organization established for civilizational resilience research since the year \
     two thousand and six. Access to individual modules is granted based on the \
     specific license tier purchased by the authorized party. Redistribution and \
     sublicensing or unauthorized sharing of this certificate is strictly prohibited \
     and may result in immediate revocation of all associated rights and privileges. \
     For license inquiries or module upgrades please contact your designated account \
     representative through the official support channel provided at the time of \
     purchase. This certificate remains valid for the duration specified in the \
     license agreement and is subject to the terms and conditions therein described."
}

// ─── Helpers ────────────────────────────────────────────────

fn hash_fingerprint(fingerprint: &str) -> String {
    let hash = Sha256::digest(fingerprint.as_bytes());
    hex_encode(&hash)
}

fn random_hex(bytes: usize) -> String {
    let random_bytes: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    hex_encode(&random_bytes)
}

fn now_iso8601() -> String {
    // Simple UTC timestamp without chrono dependency
    // Format: "2026-04-07T00:00:00Z"
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Manual conversion (good enough for license timestamps)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let month_days: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i as u64 + 1;
            break;
        }
        days -= md;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> std::result::Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn matches_domain(hostname: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        hostname.ends_with(suffix) || hostname == suffix
    } else {
        hostname == pattern
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::ZeroWidth;

    fn sample_keypair() -> (MasterKeyPair, MasterPublicKey) {
        let kp = MasterKeyPair::generate();
        let pk = kp.public_key();
        (kp, pk)
    }

    fn sample_license() -> License {
        LicenseBuilder::new("Test Corp")
            .modules(&["canary-trap", "anti-detect"])
            .build()
    }

    #[test]
    fn sign_embed_extract_verify_roundtrip() {
        let (kp, pk) = sample_keypair();
        let license = sample_license();
        let cover = default_license_cover();
        let method = ZeroWidth::new();

        let stego_text = sign_and_embed(&license, &kp, cover, &method).unwrap();

        // The stego text should look like the cover text (same visible chars)
        assert_eq!(method.strip(&stego_text), cover);

        // Extract and verify
        let extracted = extract_and_verify(&stego_text, &pk, &method).unwrap();

        assert_eq!(extracted.licensee, "Test Corp");
        assert_eq!(extracted.modules, vec!["canary-trap", "anti-detect"]);
        assert_eq!(extracted.v, 1);
    }

    #[test]
    fn tampered_stego_text_fails() {
        let (kp, pk) = sample_keypair();
        let license = sample_license();
        let method = ZeroWidth::new();

        let mut stego_text = sign_and_embed(&license, &kp, default_license_cover(), &method).unwrap();

        // Tamper: replace a zero-width char
        stego_text = stego_text.replacen('\u{200B}', "\u{200C}", 1);

        // Should fail verification (signature won't match)
        let result = extract_and_verify(&stego_text, &pk, &method);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_public_key_fails() {
        let (kp, _) = sample_keypair();
        let (_, wrong_pk) = sample_keypair(); // Different key pair!
        let license = sample_license();
        let method = ZeroWidth::new();

        let stego_text = sign_and_embed(&license, &kp, default_license_cover(), &method).unwrap();

        let result = extract_and_verify(&stego_text, &wrong_pk, &method);
        assert!(result.is_err());
    }

    #[test]
    fn module_authorization() {
        let license = sample_license();

        assert!(license.check_module("canary-trap").is_ok());
        assert!(license.check_module("anti-detect").is_ok());
        assert!(license.check_module("dlp-forensics").is_err());
    }

    #[test]
    fn wildcard_module() {
        let license = LicenseBuilder::new("Admin")
            .module("*")
            .build();

        assert!(license.check_module("anything").is_ok());
        assert!(license.check_module("even-this").is_ok());
    }

    #[test]
    fn expiry_check() {
        let license = LicenseBuilder::new("Test")
            .module("x")
            .expires("2030-12-31T23:59:59Z")
            .build();

        assert!(license.check_expiry("2026-04-07T00:00:00Z").is_ok());
        assert!(license.check_expiry("2030-12-31T23:59:59Z").is_ok());
        assert!(license.check_expiry("2031-01-01T00:00:00Z").is_err());
    }

    #[test]
    fn perpetual_license_never_expires() {
        let license = LicenseBuilder::new("Test")
            .module("x")
            .build(); // No expiry = perpetual

        assert!(license.check_expiry("2099-12-31T23:59:59Z").is_ok());
    }

    #[test]
    fn hardware_binding() {
        let license = LicenseBuilder::new("Test")
            .module("x")
            .hardware("my-machine:guid-123")
            .build();

        assert!(license.check_hardware("my-machine:guid-123").is_ok());
        assert!(license.check_hardware("other-machine:guid-456").is_err());
    }

    #[test]
    fn org_domain_matching() {
        let license = LicenseBuilder::new("Test")
            .module("x")
            .org("*.company.ch")
            .build();

        assert!(license.check_org("server1.company.ch").is_ok());
        assert!(license.check_org("company.ch").is_ok());
        assert!(license.check_org("other.org").is_err());
    }

    #[test]
    fn canary_is_unique() {
        let lic1 = sample_license();
        let lic2 = sample_license();

        // Each license gets a unique canary (for leak tracing)
        assert_ne!(lic1.canary, lic2.canary);
        assert_ne!(lic1.id, lic2.id);
    }

    #[test]
    fn machine_fingerprint_is_stable() {
        let fp1 = machine_fingerprint();
        let fp2 = machine_fingerprint();

        // Same machine should produce same fingerprint
        assert_eq!(fp1, fp2);
        assert!(!fp1.is_empty());
    }

    #[test]
    fn default_cover_has_enough_capacity() {
        // Zero-width overflows past the cover, so "enough capacity" is not a
        // raw-bit threshold (backlog F25): `capacity()` reports one bit per
        // visible position, which a full license exceeds and the overflow tail
        // absorbs. The real property is that the default cover carries a whole
        // license end to end, so that is what this asserts.
        let (kp, pk) = sample_keypair();
        let method = ZeroWidth::new();

        let stego =
            sign_and_embed(&sample_license(), &kp, default_license_cover(), &method).unwrap();
        let extracted = extract_and_verify(&stego, &pk, &method).unwrap();

        assert_eq!(extracted.licensee, "Test Corp");
    }

    // ─── Document binding, backlog F12 ──────────────────────

    /// The whole proposition: a claim that verifies says something about the
    /// document it sits in. Change one visible character and the claim must
    /// stop verifying, and say why in those words.
    #[test]
    fn altering_one_visible_character_breaks_verification() {
        let (kp, pk) = sample_keypair();
        let method = ZeroWidth::new();
        let stego = sign_and_embed(&sample_license(), &kp, default_license_cover(), &method).unwrap();

        // Recase the first visible letter, one character, nothing else. The
        // zero-width payload rides between the visible characters and is
        // untouched, so the signature over the claim still verifies and only
        // the document binding can catch this.
        let mut altered_one = false;
        let altered: String = stego
            .chars()
            .map(|c| {
                if !altered_one && c.is_ascii_lowercase() {
                    altered_one = true;
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(altered_one, "the alteration must actually land");
        assert_eq!(altered.chars().count(), stego.chars().count());

        let err = extract_and_verify(&altered, &pk, &method).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("document hash mismatch"),
            "failure must name the document binding, got: {message}"
        );
    }

    /// Appending visible text is the cheapest attack and the one the previous
    /// behaviour let through.
    #[test]
    fn appending_visible_text_breaks_verification() {
        let (kp, pk) = sample_keypair();
        let method = ZeroWidth::new();
        let stego = sign_and_embed(&sample_license(), &kp, default_license_cover(), &method).unwrap();

        let extended = format!("{stego} One more sentence, added by somebody else.");

        let err = extract_and_verify(&extended, &pk, &method).unwrap_err();
        assert!(
            err.to_string().contains("document hash mismatch"),
            "failure must name the document binding, got: {err}"
        );
    }

    /// Framing is not the document. A caller that prints its result adds a
    /// trailing newline, and that newline is an alteration like any other: the
    /// hash covers the document exactly, with no whitespace tolerance invented
    /// here that SPEC_CORE_V2 §6.4 does not define for `strip_all`. Callers
    /// that frame their output must hand the verifier the document back, not
    /// the framing around it.
    #[test]
    fn framing_added_around_a_signed_document_is_an_alteration() {
        let (kp, pk) = sample_keypair();
        let method = ZeroWidth::new();
        let stego = sign_and_embed(&sample_license(), &kp, default_license_cover(), &method).unwrap();

        let printed = format!("{stego}\n");
        let err = extract_and_verify(&printed, &pk, &method).unwrap_err();
        assert!(
            err.to_string().contains("document hash mismatch"),
            "failure must name the document binding, got: {err}"
        );

        // The document itself, with the framing taken back off, verifies.
        assert!(extract_and_verify(printed.trim_end(), &pk, &method).is_ok());
    }

    /// The counterpart: binding must not make signing unrepeatable. The same
    /// claim in the same cover verifies again, and binds to the same hash.
    #[test]
    fn re_embedding_the_same_claim_in_the_same_cover_still_verifies() {
        let (kp, pk) = sample_keypair();
        let license = sample_license();
        let cover = default_license_cover();
        let method = ZeroWidth::new();

        let first = sign_and_embed(&license, &kp, cover, &method).unwrap();
        let second = sign_and_embed(&license, &kp, cover, &method).unwrap();

        let a = extract_and_verify(&first, &pk, &method).unwrap();
        let b = extract_and_verify(&second, &pk, &method).unwrap();

        assert_eq!(a.doc_hash, b.doc_hash);
        assert_eq!(a.doc_hash, Some(document_hash(cover).unwrap()));
        assert_eq!(first, second, "same claim, same cover, same output");
    }

    /// Signing must not mutate the caller's claim, or a second call would
    /// carry the first document's hash.
    #[test]
    fn signing_leaves_the_callers_claim_unbound() {
        let (kp, _) = sample_keypair();
        let license = sample_license();
        let method = ZeroWidth::new();

        let _ = sign_and_embed(&license, &kp, default_license_cover(), &method).unwrap();

        assert_eq!(license.doc_hash, None);
    }

    /// The hash is taken after stripping, so embedding the claim does not
    /// change the figure the claim carries.
    #[test]
    fn the_document_hash_survives_the_embedding() {
        let (kp, _) = sample_keypair();
        let cover = default_license_cover();
        let method = ZeroWidth::new();

        let stego = sign_and_embed(&sample_license(), &kp, cover, &method).unwrap();

        assert_ne!(stego, cover, "the claim must actually be in there");
        assert_eq!(document_hash(&stego).unwrap(), document_hash(cover).unwrap());
    }

    /// A claim signed before document binding existed is refused by name, not
    /// with a generic invalid-signature message: its signature is intact, it
    /// simply covers less than it is now required to cover.
    #[test]
    fn a_claim_without_a_document_hash_is_refused_by_name() {
        let (kp, pk) = sample_keypair();
        let method = ZeroWidth::new();

        // Build the pre-binding package by hand: a claim with no doc_hash,
        // signed and packaged exactly as the previous version did.
        let legacy = sample_license();
        assert_eq!(legacy.doc_hash, None);
        let lic_json = serde_json::to_string(&legacy).unwrap();
        let package = SignedPackage {
            sig: hex_encode(&kp.sign(lic_json.as_bytes())),
            lic: lic_json,
        };
        let package_json = serde_json::to_string(&package).unwrap();
        let stego = method
            .encode(default_license_cover(), package_json.as_bytes())
            .unwrap();

        let err = extract_and_verify(&stego, &pk, &method).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("claim format difference"),
            "failure must name the version difference, got: {message}"
        );
        assert!(
            message.contains("no document hash"),
            "failure must say what is missing, got: {message}"
        );
    }

    /// Backlog F12b, the counterpart to F7. The strip guard used to refuse any
    /// document that held a homoglyph substitute, on the reasoning that
    /// `Homoglyph::strip()` would rewrite it. That strip is attribution-based
    /// now and leaves legitimate Cyrillic byte for byte, so a Russian document
    /// is no longer refused: it hashes to itself, which is the honest figure.
    #[test]
    fn a_cyrillic_document_hashes_to_itself_because_strip_no_longer_corrupts_it() {
        let russian = include_str!("../../../tests/corpus/cyrillic_russian.txt");

        let hashed = document_hash(russian).unwrap();
        let raw = hex_encode(&Sha256::digest(russian.as_bytes()));
        assert_eq!(
            hashed, raw,
            "strip must leave a Cyrillic document byte identical before hashing"
        );
    }

    /// Backlog F12b. A claim carried by the homoglyph channel is, by definition,
    /// a document that contains substitutes. With the obsolete strip guard gone
    /// and `Homoglyph::strip()` reverting only what it can attribute (backlog
    /// F7), the document hash is reproducible across the embedding: the signer
    /// binds to the stripped cover, and the same figure is recomputed from the
    /// marked document. (Full `extract_and_verify` over this channel is a
    /// separate matter: license.rs reads raw carrier bytes, and homoglyph's
    /// unmarked substitutable positions read back as trailing zero bytes, so
    /// the package parses only when the cover's capacity matches the claim
    /// exactly. Binding is reproducible regardless, which is what F12b unblocks.)
    #[test]
    fn a_homoglyph_claim_leaves_the_document_hash_reproducible() {
        let (kp, _) = sample_keypair();
        let method = Homoglyph::new();

        // A Latin cover with homoglyph capacity to spare for a full signed claim.
        let base =
            "The quick brown fox jumps over a lazy dog while a copy escapes precisely today. ";
        let cover = base.repeat(200);

        let before = document_hash(&cover).unwrap();
        let stego = sign_and_embed(&sample_license(), &kp, &cover, &method).unwrap();
        assert_ne!(stego, cover, "the claim must actually be carried by substitutions");

        let after = document_hash(&stego).unwrap();
        assert_eq!(
            before, after,
            "the homoglyph mark must strip back to the cover before hashing"
        );
    }

    /// Canonical order, so signer and verifier strip the same way.
    #[test]
    fn strip_all_runs_the_carriers_in_canonical_id_order() {
        let ids = [
            Bidi::new().id().to_string(),
            Homoglyph::new().id().to_string(),
            WhitespaceVar::new().id().to_string(),
            ZeroWidth::new().id().to_string(),
        ];

        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "strip_all must walk the carriers in id order");
    }

    /// Every invisible carrier's artifacts come off before the hash is taken,
    /// so a claim survives a document that is also carrying other layers.
    #[test]
    fn the_document_hash_ignores_every_invisible_carrier() {
        let clean = "A plain sentence with nothing hidden in it at all.";
        let dressed = "A plain\u{200B} sentence\u{2060} with\u{200E} nothing\u{FEFF} \
                       hidden\u{200C} in\u{202C} it\u{2063} at\u{200F} all.";

        assert_eq!(document_hash(dressed).unwrap(), document_hash(clean).unwrap());
    }

    #[test]
    fn full_lifecycle() {
        // === ADMIN SIDE ===
        let master_kp = MasterKeyPair::generate();
        let public_key_bytes = master_kp.public_key().to_bytes();

        let license = LicenseBuilder::new("Banque Suisse SA")
            .modules(&["canary-trap", "anti-detect", "watermark"])
            .org("*.banque-suisse.ch")
            .expires("2028-01-01T00:00:00Z")
            .build();

        let method = ZeroWidth::new();
        let license_text = sign_and_embed(&license, &master_kp, default_license_cover(), &method).unwrap();

        // === CLIENT SIDE ===
        // Only has the public key (embedded in binary) and the license text
        let client_pubkey = MasterPublicKey::from_bytes(&public_key_bytes).unwrap();
        let validated = extract_and_verify(&license_text, &client_pubkey, &method).unwrap();

        // Check authorizations
        assert!(validated.check_module("canary-trap").is_ok());
        assert!(validated.check_module("prompt-protect").is_err());
        assert!(validated.check_expiry("2027-06-15T00:00:00Z").is_ok());
        assert!(validated.check_org("prod.banque-suisse.ch").is_ok());
        assert!(validated.check_org("hacker.evil.com").is_err());

        assert_eq!(validated.licensee, "Banque Suisse SA");
    }
}
