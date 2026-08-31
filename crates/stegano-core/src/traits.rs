use crate::error::Result;
use crate::format::{self, PositionChannel};

// ─────────────────────────────────────────────
// Level 1: Core traits (the universal interface)
// ─────────────────────────────────────────────

/// Steganography method — hides data inside cover text.
/// Fragile by design: if detected, it's broken.
///
/// `PositionChannel` is a supertrait rather than an accessor returning an
/// option, and the choice is deliberate (backlog F19). The document format of
/// SPEC_CORE_V2 §3 *is* a frame laid over addressable positions: a carrier
/// that cannot say where its slots are cannot host a v2 document at all. An
/// `Option<&dyn PositionChannel>` would let such a carrier compile, then fail
/// at run time with an error about the cover rather than about the carrier,
/// and it would force every pre-flight caller through a branch that has no
/// honest second arm. The bound states the requirement where it can be checked.
///
/// The practical consequence is the one F19 asked for: anything holding a
/// `&dyn StegoMethod` reaches `framed_capacity_bytes` in one call, with no
/// downcast and no sizing probe.
pub trait StegoMethod: PositionChannel + Send + Sync {
    /// Unique identifier (e.g., "zero_width", "homoglyph").
    fn id(&self) -> &str;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Encode `payload` bytes into `cover` text.
    /// Returns the stego text (visually identical to cover).
    fn encode(&self, cover: &str, payload: &[u8]) -> Result<String>;

    /// Decode hidden payload from `stego` text.
    /// Returns the raw bytes that were hidden.
    fn decode(&self, stego: &str) -> Result<Vec<u8>>;

    /// How many bits can this method hide in the given cover text?
    ///
    /// One bit per substitutable position, which is what `positions()` counts.
    /// The default says exactly that, so a carrier that does not override it
    /// cannot report the figure in some other unit. The four carriers written
    /// before this default existed still override it, and one of them reports
    /// eight times the number of slots it has (backlog F25).
    ///
    /// This is the *raw* figure: what the carrier can place before the frame
    /// of SPEC_CORE_V2 §3 takes its share. No pre-flight check should be built
    /// on it. Use `framed_capacity_bytes` for what a document can carry, and
    /// `pipeline::secret_capacity_bytes` for what a secret can be.
    fn capacity(&self, cover: &str) -> usize {
        self.positions(cover)
    }

    /// Detection confidence: 0.0 = no trace, 1.0 = certain.
    fn detect(&self, text: &str) -> f64;

    /// Strip all steganographic artifacts from text, returning clean text.
    fn strip(&self, text: &str) -> String;

    /// The codepoint alphabet this carrier reads and writes — SPEC_CORE_V2 §6.5.
    ///
    /// Carriers stack by embedding into the previous carrier's output text, which
    /// is only sound while their alphabets are disjoint. The pipeline checks that
    /// with `pipeline::validate_composition` instead of trusting convention.
    ///
    /// Return every codepoint the carrier may produce *or* interpret. A carrier
    /// that substitutes visible characters returns both sides of the substitution.
    fn channel(&self) -> &'static [char];

    /// Payload bytes a framed document can carry in this cover — SPEC_CORE_V2 §3.
    ///
    /// This is `capacity()` with the frame deducted: two preamble replicas of
    /// 192 positions each, plus one 32 position resync marker per span. On the
    /// long article that takes 141 raw bytes down to 73.
    ///
    /// It is what a document holds, not what a secret may be: the envelope of
    /// §4 and its integrity step are still to come. `pipeline::capacity` takes
    /// those off as well, and that is the figure an interface should show.
    ///
    /// Never returns zero to mean "could not tell". A cover this carrier
    /// cannot work with raises, and the error names the carrier and the
    /// arithmetic (invariant 2).
    fn framed_capacity_bytes(&self, cover: &str) -> Result<usize> {
        format::capacity_bytes(self, cover)
    }
}

/// Encryption method — protects payload confidentiality + integrity.
pub trait CryptoMethod: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;

    /// Encrypt `plaintext` with `password`. Returns ciphertext bytes.
    /// Must use random salt + nonce internally (non-deterministic).
    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<Vec<u8>>;

    /// Decrypt `ciphertext` with `password`. Returns plaintext bytes.
    /// Returns `Err(DecryptionFailed)` on wrong password (not empty string!).
    fn decrypt(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>>;
}

/// Encryption method driven by the unified key tree — SPEC_CORE_V2 §2.
///
/// Complements `CryptoMethod` rather than replacing it: the key arrives already
/// derived, so the cipher generates no salt and runs no key derivation of its
/// own. A recovery sweep therefore costs one Argon2 per document instead of one
/// per candidate (§6.3).
///
/// Output format: `KEYED_VERSION(1) || NONCE || CIPHERTEXT || TAG`. The salt is
/// document state and lives in the preamble, not in every cipher's output.
pub trait KeyedCryptoMethod: Send + Sync {
    /// Same identifier as the method's `CryptoMethod` implementation.
    fn id(&self) -> &str;

    /// Exact key length this cipher requires, in bytes. Callers take the
    /// leading `key_len()` bytes of `k_enc`.
    fn key_len(&self) -> usize;

    /// Encrypt `plaintext` under a pre-derived `key`.
    /// Returns `Err(InvalidInput)` if `key` is not `key_len()` bytes long.
    fn encrypt_with_key(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt `ciphertext` under a pre-derived `key`.
    /// Returns `Err(DecryptionFailed)` when authentication fails.
    fn decrypt_with_key(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>>;
}

/// Noise injection — perturbs AI detectors without hiding data.
/// Semi-robust: survives AI detection, may not survive Unicode cleanup.
pub trait NoiseMethod: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;

    /// Inject noise into text. `intensity` is 0.0 (minimal) to 1.0 (maximum).
    fn inject(&self, text: &str, intensity: f64) -> Result<String>;

    /// Remove noise, restoring the original text (best effort).
    fn strip(&self, text: &str) -> String;

    /// Estimated impact on AI detector perplexity (0.0 = none, 1.0 = maximal).
    fn perplexity_impact(&self, text: &str) -> f64;
}

/// Watermark method — marks text for ownership/tracing.
/// Robust by design: must survive transformations.
pub trait WatermarkMethod: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;

    /// Embed a fingerprint into text.
    fn embed(&self, text: &str, fingerprint: &[u8]) -> Result<String>;

    /// Extract fingerprint from text (returns None if not found).
    fn extract(&self, text: &str) -> Result<Option<Vec<u8>>>;

    /// Resilience score: probability of surviving common transformations.
    /// 0.0 = fragile, 1.0 = indestructible.
    fn resilience(&self) -> f64;
}

// ─────────────────────────────────────────────
// Pipeline result types
// ─────────────────────────────────────────────

/// Result of an encoding operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EncodeResult {
    pub stego_text: String,
    pub methods_used: Vec<String>,
    /// Bits the framed envelope occupied.
    pub capacity_used_bits: usize,
    /// Framed bits the cover offered the narrowest carrier of the stack.
    ///
    /// Not a sum over the carriers: each one holds a complete copy of the same
    /// layer, so a stack carries what its narrowest member carries, and the
    /// raw per-carrier figures are not all in the same unit (backlog F25).
    /// Zero means the cover held no frame in its own positions, which a
    /// carrier that creates the positions it writes can still place into by
    /// extending the document. `pipeline::capacity` says which case it is.
    pub capacity_available_bits: usize,
    pub warnings: Vec<String>,
}

/// Result of a decoding operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecodeResult {
    pub hidden_data: Vec<u8>,
    pub methods_detected: Vec<String>,
    pub crypto_used: Option<String>,
    pub integrity_valid: bool,
    pub warnings: Vec<String>,
}

/// Result of a detection operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectResult {
    pub methods: Vec<DetectedMethod>,
    pub overall_confidence: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedMethod {
    pub id: String,
    pub name: String,
    pub confidence: f64,
}

/// Metrics for a stego text.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NoiseMetrics {
    /// Shannon entropy delta (after - before).
    pub shannon_delta: f64,
    /// Invisible characters / total characters.
    pub noise_density: f64,
    /// Estimated perplexity impact on AI detectors.
    pub perplexity_delta: f64,
    /// Noise Survival Score (0.0 - 1.0).
    pub survival_score: f64,
}
