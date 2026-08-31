//! Pipeline encode, decode and detect — the traced cascade of SPEC_CORE_V2 §6.
//!
//! Encode lays a document out as `format` describes it: an envelope carrying
//! the transform chain, wrapped in a frame that records how many bits were
//! written, placed by each carrier in turn into the text the previous carrier
//! produced (§6.1, §6.5).
//!
//! Decode reverses that from recorded state, never from inference. It reads
//! the preamble, replays the chain in strict reverse order, one wave per step,
//! and returns a record per wave. A wave that cannot keep its promise halts
//! the chain and names itself; nothing continues on degraded data (invariant
//! 2 and 3).
//!
//! Carrier identification is the single exception, and it is declared as such:
//! a text arrives with no statement of which carriers it holds, so the cascade
//! asks each candidate whether it can find a preamble of its own before it
//! drives anything. When none can, the decoder enters recovery mode and says
//! so (§6.3). Recovery is never silent and never a fallback the caller cannot
//! see.

use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};

use crate::crypto::keytree::SALT_LEN;
use crate::crypto::{decrypt_with_candidates, Aes128, Aes256, ChaCha20, KeyTree};
use crate::error::{Result, SteganoError};
use crate::format::{self, crc32, frame, ChainStep, Envelope, Flags, Layout, Mission, PREAMBLE_BITS};
use crate::traits::{
    CryptoMethod, DecodeResult, DetectResult, DetectedMethod, EncodeResult, KeyedCryptoMethod,
    StegoMethod,
};

/// Format of the pre-format documents this build still reads (§8).
///
/// Nothing writes it any more. It survives here because a document produced
/// before the frame existed must still be readable, and reading it has to say
/// so rather than pass it off as a current document.
#[derive(serde::Deserialize)]
struct DataPackage {
    version: String,
    data: String,
    crypto: Option<String>,
    checksum: String,
}

const PACKAGE_VERSION: &str = "2.0";

/// Identifier of the integrity step, SPEC_CORE_V2 §4.1.
///
/// A step that does not authenticate itself carries a trailing CRC-32 over its
/// output. A document with no cipher at all is covered the same way, so every
/// document has at least one exact oracle (§7, level 2).
const INTEGRITY_STEP: &str = "crc32";

/// Width of the trailing checksum the integrity step appends.
const CRC32_LEN: usize = 4;

/// How far the frame search may walk when sizing a frame for a payload.
/// Used only by the heavy-frame span sizing, kept for the secondary heavy-frame
/// mode that the light frame now defaults ahead of (invariant 1: nothing deleted).
#[allow(dead_code)]
const SPAN_SEARCH_ROUNDS: usize = 64;

/// Invisible Unicode format controls a carrier may use without touching the
/// visible text: the general-punctuation format block (U+200B..U+200F,
/// U+202A..U+202E, U+2060..U+2064, U+206A..U+206F) and U+FEFF.
///
/// A carrier whose alphabet stays inside this set adds characters between
/// visible ones; a carrier that leaves it rewrites the visible text itself.
fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{206A}'..='\u{206F}'
        | '\u{FEFF}')
}

/// Does this carrier rewrite the visible characters of the cover text?
///
/// Such a carrier changes the substitutable-position set every other carrier
/// measured, so it must run last (SPEC_CORE_V2 §6.5). Homoglyph is the one
/// implementor today; the rule is read off `channel()`, not off its id.
///
/// The same distinction decides how wide a frame is laid: a carrier that
/// rewrites visible text reads every position the document offers, so its
/// frame has to cover all of them. A carrier that inserts its own characters
/// creates exactly the positions it writes, so its frame spans only those.
fn rewrites_visible_text(method: &dyn StegoMethod) -> bool {
    method.channel().iter().any(|c| !is_invisible_format(*c))
}

/// Validate a carrier composition before any text is touched — SPEC_CORE_V2 §6.5.
///
/// Two rules, both derived from `StegoMethod::channel()`:
/// - carrier alphabets must be pairwise disjoint, since carrier N embeds into
///   the output text of carrier N-1;
/// - a carrier that rewrites visible text must run last.
///
/// Returns `ChannelCollision` or `CompositionOrder`. An empty or single-carrier
/// chain is always legal.
pub fn validate_composition(methods: &[&dyn StegoMethod]) -> Result<()> {
    for (i, first) in methods.iter().enumerate() {
        for second in methods.iter().skip(i + 1) {
            for &shared in first.channel() {
                if second.channel().contains(&shared) {
                    return Err(SteganoError::ChannelCollision {
                        first: first.id().to_string(),
                        second: second.id().to_string(),
                        codepoint: shared as u32,
                    });
                }
            }
        }
    }

    if methods.len() > 1 {
        for (i, method) in methods.iter().enumerate().take(methods.len() - 1) {
            if rewrites_visible_text(*method) {
                return Err(SteganoError::CompositionOrder {
                    carrier: method.id().to_string(),
                    successor: methods[i + 1].id().to_string(),
                });
            }
        }
    }

    Ok(())
}

// ─── The trace, SPEC_CORE_V2 §6.2 and §7 ───

/// Which oracle judged a wave, from the hierarchy of SPEC_CORE_V2 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OracleLevel {
    /// Level 1: an AEAD authentication tag. Exact.
    AeadTag,
    /// Level 2: a checksum, the preamble CRC-16 or a step's CRC-32. Exact.
    Checksum,
    /// Level 3: a statistical language score. Not implemented yet (backlog E1).
    NGram,
    /// Level 4: nothing applicable. A structural step, judged by nothing.
    NotApplicable,
}

/// What a wave concluded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum WaveVerdict {
    /// The wave did what it promised.
    Passed,
    /// The wave could not, and names why. The chain halts here.
    Failed { reason: String },
    /// Nothing was found and nothing was checkable: level 4 of §7. This is
    /// "undetermined", never "failed".
    Undetermined { reason: String },
}

/// One wave of the cascade: SPEC_CORE_V2 §6.2.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WaveRecord {
    /// The step this wave reverted: a carrier id, a chain step id, or one of
    /// the structural steps `identify`, `envelope` and `recovery_sweep`.
    pub step: String,
    /// Size the wave received, in bytes.
    pub input_bytes: usize,
    /// Size the wave produced, in bytes.
    pub output_bytes: usize,
    /// Wall time this wave took.
    pub elapsed_micros: u128,
    /// Which oracle judged it.
    pub oracle: OracleLevel,
    /// What it concluded.
    pub verdict: WaveVerdict,
}

impl WaveRecord {
    /// Did this wave halt the chain?
    pub fn is_failure(&self) -> bool {
        matches!(self.verdict, WaveVerdict::Failed { .. })
    }
}

/// A decode with its trace, whether it succeeded or not.
///
/// The trace is returned in both cases on purpose: a failed decode is only
/// diagnosable if the caller can see how far the chain got and which wave
/// stopped it.
#[derive(Debug)]
pub struct TracedDecode {
    /// What the cascade recovered, or the failure that stopped it.
    pub outcome: Result<DecodeResult>,
    /// One record per wave, in the order they ran.
    pub waves: Vec<WaveRecord>,
    /// True when no preamble was found and the candidates were swept
    /// explicitly (§6.3). Never set without a warning saying so.
    pub recovery_mode: bool,
}

impl TracedDecode {
    /// The wave that halted the chain, if one did.
    pub fn failed_wave(&self) -> Option<&WaveRecord> {
        self.waves.iter().find(|wave| wave.is_failure())
    }

    /// The step ids of the waves that ran, in order.
    pub fn steps(&self) -> Vec<&str> {
        self.waves.iter().map(|wave| wave.step.as_str()).collect()
    }
}

/// Record a wave, timing it from `started`.
fn wave(
    step: &str,
    started: Instant,
    input_bytes: usize,
    output_bytes: usize,
    oracle: OracleLevel,
    verdict: WaveVerdict,
) -> WaveRecord {
    WaveRecord {
        step: step.to_string(),
        input_bytes,
        output_bytes,
        elapsed_micros: started.elapsed().as_micros(),
        oracle,
        verdict,
    }
}

// ─── Ciphers ───

/// The keyed implementation of a cipher, when it has one.
///
/// `KeyedCryptoMethod` takes a key the pipeline derived once from the document
/// salt (§2), so a decode pays one Argon2 rather than one per attempt. The two
/// keystream references have no keyed path yet (backlog F11); they keep the
/// password-taking path and the integrity step covers their output.
fn keyed_cipher(id: &str) -> Option<Box<dyn KeyedCryptoMethod>> {
    match id {
        "aes256_gcm" => Some(Box::new(Aes256::new())),
        "aes128_gcm" => Some(Box::new(Aes128::new())),
        "chacha20_poly1305" => Some(Box::new(ChaCha20::new())),
        _ => None,
    }
}

// ─── Capacity, SPEC_CORE_V2 §3.3 ───

/// What one carrier can carry in one cover, with every deduction named.
///
/// The three figures are not variants of each other. `raw_bytes` is what the
/// carrier can place, `framed_bytes` is what a v2 document holds once §3 has
/// taken its two preamble replicas and its resync markers, and `secret_bytes`
/// is what is left after the envelope of §4 and the integrity step. Only the
/// last is a promise: place that many bytes and the engine takes them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CarrierCapacity {
    /// Carrier identifier, matching `StegoMethod::id`.
    pub carrier: String,
    /// Substitutable positions this cover offers the carrier.
    pub positions: usize,
    /// The raw figure in bytes, before the frame. Reported so a caller can see
    /// the size of the deduction rather than take it on trust.
    ///
    /// Derived from `positions`, never from `StegoMethod::capacity`. The four
    /// carriers do not report that in the same unit (backlog F25), and a field
    /// meant to make a deduction visible must not be the one place the unit
    /// confusion re-enters.
    pub raw_bytes: usize,
    /// Payload bytes the framed document holds.
    pub framed_bytes: usize,
    /// Does the cover bound this carrier, or does the carrier create the
    /// positions it writes?
    ///
    /// When true, `secret_bytes` is a limit the engine holds: one byte more is
    /// refused. When false, the carrier goes past the cover by extending the
    /// document, and `secret_bytes` is the last size that leaves the mark
    /// looking like its cover (invariant 4b) rather than a refusal boundary.
    /// A surface that shows the figure without this flag is showing half of it.
    pub cover_bounds_writes: bool,
    /// Of `framed_bytes`, how many the envelope, the integrity step and the
    /// cipher take. `secret_bytes + overhead_bytes == framed_bytes` always.
    pub overhead_bytes: usize,
    /// The largest secret this carrier accepts in this cover. Zero means the
    /// cover holds a frame but nothing else, which is a real answer.
    pub secret_bytes: usize,
}

/// What a cover can carry through a whole carrier stack.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Capacity {
    /// One entry per carrier, in the order the stack applies them.
    pub carriers: Vec<CarrierCapacity>,
    /// The binding figure: the smallest secret any carrier in the stack takes.
    pub secret_bytes: usize,
}

/// The chain `seal` will record for this cipher choice, and the bytes the
/// cipher adds to the secret.
///
/// Measured, never assumed. A keyed cipher is asked to expand a probe under a
/// throwaway key, which costs no key derivation at all; a cipher with no keyed
/// path is asked under the passcode it was given, which costs one derivation.
/// Hard coding "version byte, nonce, tag, so twenty nine" would be a number
/// free to drift away from the cipher it claims to describe.
fn seal_shape(crypto: Option<(&dyn CryptoMethod, &str)>) -> Result<(Vec<ChainStep>, usize)> {
    /// Probe length for measuring cipher expansion. Any length does, since the
    /// expansion of every cipher here is a fixed prefix and suffix.
    const PROBE_LEN: usize = 16;

    fn expansion(id: &str, expanded: usize) -> Result<usize> {
        expanded.checked_sub(PROBE_LEN).ok_or_else(|| {
            SteganoError::EncodingFailed {
                method: id.to_string(),
                reason: format!(
                    "this cipher returned {expanded} bytes for a {PROBE_LEN} byte probe, so its \
                     cost cannot be deducted from a capacity"
                ),
            }
        })
    }

    let integrity_only = || (vec![ChainStep::new(INTEGRITY_STEP, Vec::new())], CRC32_LEN);

    let Some((method, password)) = crypto else {
        return Ok(integrity_only());
    };
    if password.is_empty() {
        // An empty passcode means no cipher, which `seal` treats the same way.
        return Ok(integrity_only());
    }

    match keyed_cipher(method.id()) {
        Some(keyed) => {
            let key = vec![0u8; keyed.key_len()];
            let expanded = keyed.encrypt_with_key(&[0u8; PROBE_LEN], &key)?;
            Ok((
                vec![ChainStep::new(method.id(), Vec::new())],
                expansion(method.id(), expanded.len())?,
            ))
        }
        None => {
            // No keyed path, so this cipher does not authenticate its output
            // and `seal` covers it with the integrity step as well.
            let expanded = method.encrypt(&[0u8; PROBE_LEN], password)?;
            Ok((
                vec![
                    ChainStep::new(method.id(), Vec::new()),
                    ChainStep::new(INTEGRITY_STEP, Vec::new()),
                ],
                expansion(method.id(), expanded.len())? + CRC32_LEN,
            ))
        }
    }
}

/// Serialised size of the envelope `seal` produces around `payload_len` bytes.
fn envelope_len(chain: &[ChainStep], payload_len: usize) -> Result<usize> {
    Ok(Envelope::new(chain.to_vec(), vec![0u8; payload_len])
        .to_bytes()?
        .len())
}

/// Which frame the encoder writes. The light frame (§3.2) is the default and the
/// base of the multi-pass composition: a single minimal header, no replica, no
/// resync markers, so it carries text in little cover. The heavy frame (§3) is
/// the secondary, recovery-robust mode: two preamble replicas and resync markers
/// for surviving a partly damaged or excerpted document, at a much larger
/// overhead. The operator chooses it; nothing here infers it (invariant 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameMode {
    #[default]
    Light,
    Heavy,
}

impl FrameMode {
    /// The heavy, recovery-robust frame when `robust` is set, else the light
    /// default. The one place a surface's boolean toggle becomes the mode.
    pub fn from_robust(robust: bool) -> Self {
        if robust {
            FrameMode::Heavy
        } else {
            FrameMode::Light
        }
    }
}

/// The payload bytes a cover's `positions` hold under a given frame, its header
/// deducted, so a capacity figure and the engine agree for either frame. The
/// heavy frame reports zero where its preamble replicas and markers do not fit,
/// an honest figure the carrier then refuses to place into.
fn framed_room(positions: usize, has_salt: bool, frame_mode: FrameMode) -> usize {
    match frame_mode {
        FrameMode::Light => format::frame_light::payload_capacity_bytes(positions, has_salt),
        FrameMode::Heavy => frame::payload_capacity_bytes(positions).unwrap_or(0),
    }
}

/// Whether the light frame will carry a salt for this cipher choice. Only a
/// keyed cipher under a non-empty passcode rides its salt into the frame, and
/// that is the one case whose header is the sealed 24 bytes rather than the
/// plain 8. The capacity report deducts the header the engine will write.
fn frame_carries_salt(crypto: Option<(&dyn CryptoMethod, &str)>) -> bool {
    matches!(crypto, Some((method, password))
        if !password.is_empty() && keyed_cipher(method.id()).is_some())
}

/// The largest secret one carrier takes in one cover, given the cipher and frame.
fn carrier_capacity(
    method: &dyn StegoMethod,
    cover: &str,
    chain: &[ChainStep],
    cipher_overhead: usize,
    has_salt: bool,
    frame_mode: FrameMode,
) -> Result<CarrierCapacity> {
    // A cover the carrier will not write into has no figure, and saying so by
    // name is the answer. Never a zero standing in for "could not tell".
    method.check_writable(cover)?;

    let bounded = format::cover_bounds_writes(method, cover);
    let positions = method.positions(cover);
    // The reported figure is the chosen frame's budget: the carrier's positions,
    // less the header the frame writes (the light frame's 8 plain / 24 sealed
    // bytes, or the heavy frame's two preamble replicas and markers). This is
    // exactly what `place_layer` writes for that frame, so the report and the
    // engine agree byte for byte, which the corpus suite holds on every document.
    let framed = framed_room(positions, has_salt, frame_mode);

    // The envelope grows by one byte at each postcard varint boundary, so the
    // largest secret is searched for rather than subtracted. The function is
    // monotone and the frame already bounds the range, so this terminates in
    // the width of the frame in bits.
    let mut low = 0usize;
    let mut high = framed;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if envelope_len(chain, mid + cipher_overhead)? <= framed {
            low = mid;
        } else {
            high = mid - 1;
        }
    }

    Ok(CarrierCapacity {
        carrier: method.id().to_string(),
        positions,
        raw_bytes: positions / 8,
        framed_bytes: framed,
        cover_bounds_writes: bounded,
        overhead_bytes: framed - low,
        secret_bytes: low,
    })
}

/// The largest secret this cover takes, per carrier and for the stack.
///
/// This is the figure an interface should show and a pre-flight check should
/// use. It is not an estimate: `encode` accepts exactly `secret_bytes` and
/// refuses one byte more, which the corpus suite holds it to on every document
/// and every carrier.
///
/// Every carrier is measured against the cover itself, and for a stack that is
/// exact rather than approximate. Carrier N receives the text carrier N-1
/// produced, which is the cover plus inserted characters, so it never has
/// fewer positions than it has here; and the one carrier that rewrites visible
/// text must run last (§6.5), where insertions have left its own position set
/// untouched. The minimum is therefore the figure the stack holds to.
pub fn capacity(
    cover: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
) -> Result<Capacity> {
    capacity_framed(cover, stego_methods, crypto, FrameMode::Light)
}

/// `capacity` for a chosen frame. The light frame is the default the plain
/// `capacity` reports; the heavy frame's larger overhead is deducted when the
/// operator has selected the recovery-robust mode, so the pre-flight figure
/// matches the frame the engine will actually write.
pub fn capacity_framed(
    cover: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    frame_mode: FrameMode,
) -> Result<Capacity> {
    if stego_methods.is_empty() {
        return Err(SteganoError::InvalidInput(
            "at least one stego method required".into(),
        ));
    }
    validate_composition(stego_methods)?;

    let (chain, cipher_overhead) = seal_shape(crypto)?;
    let has_salt = frame_carries_salt(crypto);
    let mut carriers = Vec::with_capacity(stego_methods.len());
    for method in stego_methods {
        carriers.push(carrier_capacity(
            *method,
            cover,
            &chain,
            cipher_overhead,
            has_salt,
            frame_mode,
        )?);
    }

    let secret_bytes = carriers
        .iter()
        .map(|c| c.secret_bytes)
        .min()
        .unwrap_or_default();

    Ok(Capacity {
        carriers,
        secret_bytes,
    })
}

/// The binding figure of `capacity`, for callers that want only the number.
pub fn secret_capacity_bytes(
    cover: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
) -> Result<usize> {
    capacity(cover, stego_methods, crypto).map(|c| c.secret_bytes)
}

/// `secret_capacity_bytes` for a chosen frame.
pub fn secret_capacity_bytes_framed(
    cover: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    frame_mode: FrameMode,
) -> Result<usize> {
    capacity_framed(cover, stego_methods, crypto, frame_mode).map(|c| c.secret_bytes)
}

// ─── Recommendation ───

/// The lowercase id of a mission, the same token the surfaces accept and echo.
pub fn mission_id(mission: Mission) -> &'static str {
    match mission {
        Mission::Conceal => "conceal",
        Mission::Sign => "sign",
        Mission::Mark => "mark",
    }
}

/// Missions from strictest concealment to most permissive: the order the
/// recommendation searches, so it prefers the most invisible setting that still
/// holds the load.
const MISSIONS_STRICTEST_FIRST: [Mission; 3] = [Mission::Conceal, Mission::Sign, Mission::Mark];

/// How one carrier fits a specific secret, and the strictest mission whose
/// density ceiling the load stays under on it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CarrierFit {
    /// Carrier identifier, matching `StegoMethod::id`.
    pub carrier: String,
    /// Substitutable positions this cover offers the carrier.
    pub positions: usize,
    /// Envelope bytes this carrier's light frame holds: its room for the load.
    pub frame_capacity_bytes: usize,
    /// Whether the sealed secret fits this carrier's frame at all.
    pub holds_frame: bool,
    /// The fill ratio the load reaches here, envelope bits over positions, the
    /// figure the mission ceiling is compared against. A carrier with no
    /// positions reports a full 1.0 rather than dividing by zero.
    pub fill_ratio: f64,
    /// The strictest mission ("conceal" < "sign" < "mark") whose density ceiling
    /// this load clears on this carrier while its frame also holds it, or `None`
    /// when even Mark overflows or the frame will not take it.
    pub strictest_mission: Option<String>,
}

/// A settings recommendation for hiding one secret in one cover: which carrier,
/// mission and density hold it with the most margin and no overflow, and, when
/// nothing does, how far short the cover falls.
///
/// It invents no capacity. Every figure is the one the engine itself enforces:
/// the frame room is `frame_light::payload_capacity_bytes`, the density budget
/// is the SPEC_CORE_V2 §5.3 arithmetic the mission gate applies, and the sealed
/// envelope length is measured through the same `seal_shape` the encoder uses.
/// A surface renders the advice; the numbers here are facts, not estimates.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Recommendation {
    /// The secret length the advice was computed for.
    pub secret_bytes: usize,
    /// The sealed envelope the carriers must hold: the secret plus the cipher
    /// and integrity overhead this cipher choice adds.
    pub envelope_bytes: usize,
    /// One entry per candidate carrier, best first (strictest mission, then most
    /// margin).
    pub carriers: Vec<CarrierFit>,
    /// The recommended carrier: the one that holds the load at the strictest
    /// mission with the most margin. `None` when no carrier holds it.
    pub carrier: Option<String>,
    /// The recommended mission id, the strictest whose ceiling the load clears
    /// on the recommended carrier. `None` when nothing holds it.
    pub mission: Option<String>,
    /// The density to set for that mission: its recommended ceiling
    /// (`ceiling_for`). `None` when nothing holds it.
    pub density: Option<f64>,
    /// Whether some carrier holds the load without overflow.
    pub fits: bool,
    /// When nothing fits, the extra envelope bytes the best-placed carrier is
    /// short by, measured at the most permissive mission (Mark). Zero when it
    /// fits.
    pub shortfall_bytes: usize,
}

/// Recommend the settings that hide `secret` in `cover` with the most margin and
/// no overflow, evaluating each candidate carrier on its own (a stack carries
/// what its narrowest member does, so the best single carrier is the honest
/// suggestion; a caller keeping a stack reads each member's fit from `carriers`).
pub fn recommend(
    cover: &str,
    secret: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
) -> Result<Recommendation> {
    recommend_framed(cover, secret, stego_methods, crypto, FrameMode::Light)
}

/// `recommend` for a chosen frame. The advice is computed against the frame the
/// operator has selected, so the fit and the density it reports are the ones
/// that frame's compose will actually hold.
pub fn recommend_framed(
    cover: &str,
    secret: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    frame_mode: FrameMode,
) -> Result<Recommendation> {
    if stego_methods.is_empty() {
        return Err(SteganoError::InvalidInput(
            "at least one stego method required".into(),
        ));
    }

    let (chain, cipher_overhead) = seal_shape(crypto)?;
    let has_salt = frame_carries_salt(crypto);
    let envelope_bytes = envelope_len(&chain, secret.len() + cipher_overhead)?;

    let mut carriers: Vec<CarrierFit> = Vec::with_capacity(stego_methods.len());
    for method in stego_methods {
        let positions = method.positions(cover);
        let frame_capacity_bytes = framed_room(positions, has_salt, frame_mode);
        let holds_frame = envelope_bytes <= frame_capacity_bytes;
        let fill_ratio = if positions == 0 {
            1.0
        } else {
            (envelope_bytes * 8) as f64 / positions as f64
        };
        let strictest = MISSIONS_STRICTEST_FIRST.iter().copied().find(|mission| {
            let ceiling = crate::fidelity::density::ceiling_for(*mission);
            let budget = ((positions as f64) * ceiling / 8.0).floor() as usize;
            holds_frame && envelope_bytes <= budget
        });
        carriers.push(CarrierFit {
            carrier: method.id().to_string(),
            positions,
            frame_capacity_bytes,
            holds_frame,
            fill_ratio,
            strictest_mission: strictest.map(|m| mission_id(m).to_string()),
        });
    }

    // Rank of a mission id for "strictest first": Conceal 0, Sign 1, Mark 2.
    fn mission_rank(id: &str) -> u8 {
        match id {
            "conceal" => 0,
            "sign" => 1,
            _ => 2,
        }
    }

    // Best-first order for display and for the pick: a carrier that holds the
    // load ranks by the strictness of its best mission, then by margin (lower
    // fill ratio). A carrier that holds nothing sinks below every one that does.
    carriers.sort_by(|a, b| {
        let rank = |c: &CarrierFit| c.strictest_mission.as_deref().map(mission_rank).unwrap_or(u8::MAX);
        rank(a)
            .cmp(&rank(b))
            .then(a.fill_ratio.partial_cmp(&b.fill_ratio).unwrap_or(std::cmp::Ordering::Equal))
    });

    let best = carriers.iter().find(|c| c.strictest_mission.is_some());
    let (carrier, mission, density, fits) = match best {
        Some(c) => {
            let mission = c.strictest_mission.clone();
            let density = mission
                .as_deref()
                .and_then(mission_from_lowercase)
                .map(crate::fidelity::density::ceiling_for);
            (Some(c.carrier.clone()), mission, density, true)
        }
        None => (None, None, None, false),
    };

    // When nothing fits, how far short the best-placed carrier is at the most
    // permissive mission (Mark): the smaller of what its frame holds and what
    // Mark's ceiling budgets, maximised over the carriers.
    let shortfall_bytes = if fits {
        0
    } else {
        let mark_ceiling = crate::fidelity::density::ceiling_for(Mission::Mark);
        let best_hold = carriers
            .iter()
            .map(|c| {
                let budget = ((c.positions as f64) * mark_ceiling / 8.0).floor() as usize;
                c.frame_capacity_bytes.min(budget)
            })
            .max()
            .unwrap_or(0);
        envelope_bytes.saturating_sub(best_hold)
    };

    Ok(Recommendation {
        secret_bytes: secret.len(),
        envelope_bytes,
        carriers,
        carrier,
        mission,
        density,
        fits,
        shortfall_bytes,
    })
}

/// The mission a lowercase id names, or `None` for an unknown token. The inverse
/// of `mission_id`, kept beside it so the pair cannot drift.
pub fn mission_from_lowercase(id: &str) -> Option<Mission> {
    match id {
        "conceal" => Some(Mission::Conceal),
        "sign" => Some(Mission::Sign),
        "mark" => Some(Mission::Mark),
        _ => None,
    }
}

// ─── Encode ───

/// Seal the secret into an envelope, and report the document salt it belongs
/// with.
///
/// The chain records what was applied, in application order, so the decoder
/// replays it in reverse from recorded state rather than guessing (§4).
fn seal(
    hidden: &[u8],
    crypto: Option<(&dyn CryptoMethod, &str)>,
) -> Result<([u8; SALT_LEN], Vec<u8>, bool)> {
    let mut chain: Vec<ChainStep> = Vec::new();
    let mut payload = hidden.to_vec();
    let mut authenticated = false;
    let mut salt: [u8; SALT_LEN] = rand::random();

    if let Some((method, password)) = crypto {
        if !password.is_empty() {
            match keyed_cipher(method.id()) {
                Some(keyed) => {
                    // §2: one derivation per document, salt recorded in the
                    // preamble so the reader can repeat it exactly once.
                    let keys = KeyTree::generate(password)?;
                    payload = keyed.encrypt_with_key(&payload, &keys.k_enc()[..keyed.key_len()])?;
                    salt = *keys.salt();
                    authenticated = true;
                }
                None => {
                    payload = method.encrypt(&payload, password)?;
                }
            }
            chain.push(ChainStep::new(method.id(), Vec::new()));
        }
    }

    if !authenticated {
        payload.extend_from_slice(&crc32(&payload).to_be_bytes());
        chain.push(ChainStep::new(INTEGRITY_STEP, Vec::new()));
    }

    // The salt is meaningful only when a keyed cipher derived a key from it; the
    // light frame carries it exactly then, so a plain document pays no salt.
    Ok((salt, Envelope::new(chain, payload).to_bytes()?, authenticated))
}

/// The smallest heavy frame that holds `payload_bits` of payload.
///
/// Used by carriers that create the positions they write: their frame spans
/// what it places and leaves the rest of the document untouched. Carriers that
/// rewrite visible text cannot do this, since they read back every position
/// the document offers whether it was written to or not.
///
/// Kept for the secondary heavy-frame mode; the light frame, now the default,
/// needs no span (invariant 1: nothing deleted).
#[allow(dead_code)]
fn minimum_span(payload_bits: usize) -> Result<usize> {
    let mut span = 2 * PREAMBLE_BITS + payload_bits;
    span += (8 - span % 8) % 8;

    let mut free = 0;
    for _ in 0..SPAN_SEARCH_ROUNDS {
        let layout = Layout::for_positions(span)?;
        free = layout.payload_capacity_bits();
        if free >= payload_bits {
            return Ok(span);
        }
        // The shortfall is the resync markers this span turned out to need.
        let deficit = payload_bits - free;
        span += deficit + (8 - deficit % 8) % 8;
    }

    Err(SteganoError::CapacityExceeded {
        needed: payload_bits,
        available: free,
    })
}

/// Frame `envelope` and place it in `cover` with one carrier.
///
/// The frame decides which bits the carrier receives; the carrier alone
/// decides where they land (invariant 4). The layer is read back before it is
/// returned: a carrier whose written and read positions diverge on this cover
/// produces a document that cannot be decoded, and handing that over would be
/// exactly the silent degradation invariant 2 forbids.
///
/// The read back stays, and the reason is measured rather than assumed
/// (backlog F19). Two questions can now be asked before any text is produced,
/// and `encode` asks both: will this carrier work with this cover, and does
/// the payload fit. Neither answers the third, which is whether write and read
/// agree on this pair, and that is the question F26 turned out to be a live
/// instance of. Removing the check leaves the whole suite green, which is a
/// statement about coverage rather than about necessity, so
/// `a_carrier_whose_read_disagrees_with_its_write_is_caught_before_the_document_is_returned`
/// now exercises it deliberately. The cost was measured at the same time: the
/// corpus capacity suite runs 10.14 s with the read back and 9.71 s without,
/// about four percent, on a path where Argon2id at 64 MiB is the real expense.
fn place_layer(
    method: &dyn StegoMethod,
    cover: &str,
    salt: [u8; SALT_LEN],
    envelope: &[u8],
    keyed: bool,
    frame_mode: FrameMode,
) -> Result<String> {
    let bits = match frame_mode {
        // The light frame is the default (SPEC_CORE_V2 §3.2): a single minimal
        // header and the payload, no second replica and no resync markers, so the
        // multi-pass composition carries text in little cover. It needs no span:
        // it is exactly its header plus payload, and a carrier that reads back
        // more positions than were written has them trimmed by the frame's own
        // length field. The salt rides only when a keyed cipher used it.
        FrameMode::Light => {
            let salt_opt = if keyed { Some(salt) } else { None };
            format::frame_light::build_light(Flags::conceal(), salt_opt, envelope)?
        }
        // The heavy frame (§3) is the recovery-robust secondary mode: two preamble
        // replicas and resync markers, spanning what the carrier will place. A
        // carrier that rewrites visible text frames the whole cover; one that
        // inserts its own characters frames only what it places, sized to the
        // payload. The salt always rides, as it did before the light default.
        FrameMode::Heavy => {
            let span = if rewrites_visible_text(method) {
                method.capacity(cover)
            } else {
                minimum_span(envelope.len() * 8)?
            };
            format::build(span, Flags::conceal(), salt, envelope)?
        }
    };
    let stego = method.encode(cover, &frame::bits_to_bytes(&bits))?;

    match read_layer(method, &stego) {
        Ok(contents) if contents.payload == envelope => Ok(stego),
        Ok(_) => Err(SteganoError::EncodingFailed {
            method: method.id().to_string(),
            reason: "the layer read back from the document it produced is not the layer that \
                     was written into it"
                .into(),
        }),
        Err(e) => Err(SteganoError::EncodingFailed {
            method: method.id().to_string(),
            reason: format!("the layer could not be read back from the document it produced: {e}"),
        }),
    }
}

/// Fill a carrier's channel with the light-framed envelope repeated to the
/// carrier's capacity: the saturation placement (SAT-CORE-1, docs/SPEC_SATURATE).
///
/// The first frame is always whole and intact, so `read_layer` recovers the
/// envelope from it and the length field trims any partial tail on read; the
/// copies past the first are the redundancy. The carrier's own placement routine
/// is reused unchanged (invariant 4): only the number of bits handed to it
/// changes, from one frame to as many as its positions hold. A cover too small
/// for even one frame gets exactly one, which an inserting carrier overflows and
/// a bounded carrier refuses by name, exactly as a plain single placement does.
fn place_saturated(
    method: &dyn StegoMethod,
    cover: &str,
    framed_bits: &[u8],
    envelope: &[u8],
) -> Result<String> {
    method.check_writable(cover)?;

    // Whole frames only, so the channel stays a whole number of bytes and every
    // copy is intact (a fragment that keeps any one frame still recovers). At
    // least one copy: a cover too small even for that is left to the carrier,
    // which overflows it (an inserting carrier) or refuses by name (a bounded one).
    let positions = method.positions(cover);
    let copies = (positions / framed_bits.len()).max(1);
    let bits: Vec<u8> = framed_bits.repeat(copies);
    let stego = method.write_positions(cover, &bits)?;

    // The saturated document must still read back to the same envelope from its
    // first frame, or it is a failure that only looks like a result (invariant 2).
    match read_layer(method, &stego) {
        Ok(contents) if contents.payload == envelope => Ok(stego),
        Ok(_) => Err(SteganoError::EncodingFailed {
            method: method.id().to_string(),
            reason: "the saturated layer read back is not the envelope that was written".into(),
        }),
        Err(e) => Err(SteganoError::EncodingFailed {
            method: method.id().to_string(),
            reason: format!("the saturated layer could not be read back: {e}"),
        }),
    }
}

/// Encode a secret into cover text — SPEC_CORE_V2 §6.1.
///
/// ```text
/// secret -> [cipher] -> [integrity] -> envelope -> frame -> carrier 1 .. N
/// ```
///
/// Carriers stack: carrier N places its layer into the text carrier N-1
/// produced (§6.5), and each carries a complete copy, so a document that
/// survives with one channel intact still reads. An empty password means no
/// cipher, which is the Python behaviour and not an error.
///
/// This is the mission-agnostic entry point: it delegates to
/// `encode_for_mission` with no mission, which is today's overflow-allowed
/// behaviour (backlog F19b). Every existing caller keeps this exact signature.
pub fn encode(
    cover: &str,
    hidden: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
) -> Result<EncodeResult> {
    encode_for_mission(cover, hidden, stego_methods, crypto, None)
}

/// Encode under a declared mission, writing the default light frame. The
/// frame-choosing form is `encode_for_mission_framed`.
pub fn encode_for_mission(
    cover: &str,
    hidden: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    mission: Option<Mission>,
) -> Result<EncodeResult> {
    encode_for_mission_framed(cover, hidden, stego_methods, crypto, mission, FrameMode::Light)
}

/// Encode with a chosen frame and no mission gate: the entry a compose surface
/// uses to offer the recovery-robust heavy frame as an opt-in alongside the
/// light default.
pub fn encode_with_frame(
    cover: &str,
    hidden: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    frame_mode: FrameMode,
) -> Result<EncodeResult> {
    encode_for_mission_framed(cover, hidden, stego_methods, crypto, None, frame_mode)
}

/// Encode a secret in the saturation mode: the aggressive variant that fills each
/// chosen carrier's channel to its maximum with the framed envelope repeated
/// (SAT-CORE-1, docs/SPEC_SATURATE).
///
/// The secret is sealed exactly as elsewhere, so a passphrase cipher (AES or
/// ChaCha) or a post-quantum recipient seal composes with it; saturation is only
/// a placement choice, downstream of confidentiality. Each selected carrier
/// saturates its own channel on the running text, so a stack of carriers is
/// multi-method saturation, each an independent, redundant, recoverable channel.
/// The visible text is untouched; only the invisible channel is filled, and the
/// analyser reports the density it produces (invariant 4b, a declared opt-in).
pub fn encode_saturated(
    cover: &str,
    hidden: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
) -> Result<EncodeResult> {
    if stego_methods.is_empty() {
        return Err(SteganoError::InvalidInput(
            "at least one stego method required".into(),
        ));
    }
    if hidden.is_empty() {
        return Err(SteganoError::InvalidInput("nothing to hide".into()));
    }
    validate_composition(stego_methods)?;

    let (salt, envelope, keyed) = seal(hidden, crypto)?;
    let salt_opt = if keyed { Some(salt) } else { None };
    let framed_bits = format::frame_light::build_light(Flags::conceal(), salt_opt, &envelope)?;

    let mut current_text = cover.to_string();
    let mut methods_used = Vec::with_capacity(stego_methods.len());
    let mut filled_bits = usize::MAX;
    for method in stego_methods {
        filled_bits = filled_bits.min(method.positions(&current_text).max(framed_bits.len()));
        current_text = place_saturated(*method, &current_text, &framed_bits, &envelope)?;
        methods_used.push(method.id().to_string());
    }

    Ok(EncodeResult {
        stego_text: current_text,
        methods_used,
        capacity_used_bits: framed_bits.len(),
        capacity_available_bits: filled_bits.saturating_mul(1),
        warnings: Vec::new(),
    })
}

/// Encode choosing between the framed placement and the saturation placement:
/// the one entry a surface's compose calls with both of its toggles. When
/// `saturate` is on, the aggressive variant fills the channel (the frame choice
/// does not apply, since saturation always writes the light frame repeated);
/// otherwise the normal placement writes the chosen frame once.
pub fn encode_composed(
    cover: &str,
    hidden: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    frame_mode: FrameMode,
    saturate: bool,
) -> Result<EncodeResult> {
    if saturate {
        encode_saturated(cover, hidden, stego_methods, crypto)
    } else {
        encode_with_frame(cover, hidden, stego_methods, crypto, frame_mode)
    }
}

/// Encode a secret into cover text under a declared mission — SPEC_CORE_V2 §6.1.
///
/// The shape is a separate function taking `Option<Mission>` rather than a new
/// required argument on `encode`, and the choice is deliberate (backlog F19b).
/// `None` means "no mission specified" and keeps today's behaviour exactly: an
/// unbounded carrier overflows past the cover and the result is returned. That
/// default is what makes the change purely additive, so every one of the
/// existing callers of `encode` compiles and behaves unchanged.
///
/// A declared mission gates overflow only where the mission's whole point is
/// appearance. `Conceal` (invariant 4b is the product) refuses to write past
/// its density ceiling by named arithmetic. `Sign` and `Mark` allow overflow,
/// because redundancy and survival dominate appearance; the caller reads the
/// resulting density and the analyser's own verdict through `overflow_report`
/// on the produced document, so the choice is made with eyes open (invariant 2).
///
/// The carrier is untouched (invariant 4): the gate lives here, at the pipeline
/// layer, and the six feature tests that assert the unbounded property still
/// pass unchanged.
pub fn encode_for_mission_framed(
    cover: &str,
    hidden: &[u8],
    stego_methods: &[&dyn StegoMethod],
    crypto: Option<(&dyn CryptoMethod, &str)>,
    mission: Option<Mission>,
    frame_mode: FrameMode,
) -> Result<EncodeResult> {
    if stego_methods.is_empty() {
        return Err(SteganoError::InvalidInput(
            "at least one stego method required".into(),
        ));
    }
    if hidden.is_empty() {
        return Err(SteganoError::InvalidInput("nothing to hide".into()));
    }
    // Carriers stack on each other's output: reject an unsound stack here,
    // before any text is produced (SPEC_CORE_V2 §6.5).
    validate_composition(stego_methods)?;

    let warnings = Vec::new();
    let (salt, envelope, keyed) = seal(hidden, crypto)?;
    let needed = envelope.len() * 8;

    let mut current_text = cover.to_string();
    let mut methods_used = Vec::new();
    let mut binding_room = usize::MAX;
    for method in stego_methods {
        // Conceal gate (backlog F19b). Where the mission is concealment, the
        // document must stay under its density ceiling: overflow past it is the
        // very thing invariant 4b forbids, and an unbounded carrier reaches it
        // by extending the document rather than by refusing, so the carrier's
        // own capacity check will not catch it. The refusal is named arithmetic,
        // SPEC_CORE_V2 §5.3: the positions this carrier has to write into, times
        // the Conceal ceiling, is the bit budget; a byte past it raises rather
        // than truncating (invariant 2). Only Conceal is gated; Sign and Mark
        // allow overflow and report it. The carrier is never touched.
        if mission == Some(Mission::Conceal) {
            let positions = method.positions(&current_text);
            let ceiling = crate::fidelity::density::ceiling_for(Mission::Conceal);
            let available = ((positions as f64) * ceiling / 8.0).floor() as usize;
            if envelope.len() > available {
                return Err(SteganoError::CapacityExceeded {
                    needed,
                    available: available * 8,
                });
            }
        }

        // Ask before placing, rather than place and then read back to find out
        // (backlog F19). The question is put to the text this carrier is about
        // to receive, before a character moves.
        //
        // Only a carrier the cover bounds is held to the figure. A carrier that
        // creates the positions it writes is not bounded by the cover, so
        // refusing it here would not be a capacity check, it would be a product
        // decision to drop the overflow tail that invariant 4 says to preserve.
        // What the cover holds is still measured and still reported, by
        // `capacity`, together with the fact that this carrier will go past it.
        //
        // The gate answers one question, "does it fit", and only that one. A
        // cover this carrier will not work with at all is a different refusal
        // and belongs to the carrier, which `place_layer` reaches on the next
        // line and which names the material already in the channel. Nothing is
        // swallowed here: a sizing that could not be done is followed
        // immediately by the refusal that explains why.
        // The gate deducts the light frame's header (§3.2), the same frame
        // `place_layer` writes below, so a load the report advertised as fitting
        // is never refused here and one byte past it always is. The heavy
        // frame's larger deduction is the secondary path, not this figure.
        //
        // Only a cover this carrier can write is sized here. A cover it will not
        // work with at all (its alphabet already present) is a different refusal
        // and belongs to the carrier, which `place_layer` reaches on the next
        // line and which names the material already in the channel. Sizing it
        // would speak over that named refusal with a capacity number.
        if method.check_writable(&current_text).is_ok() {
            let room = framed_room(method.positions(&current_text), keyed, frame_mode);
            binding_room = binding_room.min(room);
            if envelope.len() > room && format::cover_bounds_writes(*method, &current_text) {
                return Err(SteganoError::CapacityExceeded {
                    needed,
                    available: room * 8,
                });
            }
        } else {
            binding_room = 0;
        }

        current_text = place_layer(*method, &current_text, salt, &envelope, keyed, frame_mode)?;
        methods_used.push(method.id().to_string());
    }

    Ok(EncodeResult {
        stego_text: current_text,
        methods_used,
        capacity_used_bits: needed,
        // The framed figure of the carrier that had least room, not the sum of
        // the raw carrier figures. A sum over a stack was never a capacity:
        // each carrier holds a complete copy of the same layer, so the stack
        // carries what its narrowest member carries, and the raw figures are
        // not all reported in the same unit (backlog F25).
        capacity_available_bits: binding_room.saturating_mul(8),
        warnings,
    })
}

/// Density and analyser verdict for a produced document — backlog F19b.
///
/// `Sign` and `Mark` allow an unbounded carrier to overflow the cover, so the
/// choice has to be made with the evidence in view (invariant 2). This carries
/// what the tool's own analysers return on the document that was produced: the
/// channel density `metrics::noise_density` measures, and the summary verdict
/// `forensic::analyze` reaches. It invents no new analyser; it surfaces the two
/// that already exist so an encode surface can report them beside the result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OverflowReport {
    /// `metrics::noise_density` on the produced document: invisible channel
    /// characters over total characters.
    pub noise_density: f64,
    /// The `forensic::analyze` summary verdict, e.g. "CONFIRMED".
    pub verdict: String,
}

/// Report the density and analyser verdict a produced document reaches (F19b).
///
/// The figure a `Sign` or `Mark` surface shows next to an overflow result. Read
/// off the finished document, so it is what an analyst would measure, not an
/// estimate.
pub fn overflow_report(marked_text: &str) -> OverflowReport {
    OverflowReport {
        noise_density: crate::metrics::noise_density(marked_text),
        verdict: crate::forensic::analyze(marked_text).verdict.to_string(),
    }
}

// ─── Decode ───

/// The bit stream one carrier reads out of a text.
///
/// A carrier that finds nothing to read reads no bits, which is an answer and
/// not an error: identification asks every candidate this question. Read by
/// position, not byte-decoded, so a saturated excerpt ending on a partial byte is
/// still offered its bits; the frame's own checksum is the real validation
/// (SAT-CORE-2).
fn layer_bits(method: &dyn StegoMethod, text: &str) -> Vec<u8> {
    method.read_positions(text)
}

/// The frame one carrier holds in a text, or the reason it does not.
fn read_layer(method: &dyn StegoMethod, text: &str) -> Result<format::FrameContents> {
    // The raw channel bits, read by position rather than byte-decoded: a saturated
    // excerpt can end on a partial byte, and the frame's own header checksum is the
    // real validation, so the frame reader works on the bits directly (SAT-CORE-2).
    let bits = method.read_positions(text);
    // Dispatch on the version byte: the light frame (the default) and the heavy
    // frame are told apart by it, never guessed (invariant 2). A light frame is
    // lifted into the same FrameContents shape the rest of the decode expects; a
    // plain light frame carries no salt, so a zero salt stands in and is never
    // used because a plain document runs no key derivation.
    fn from_light(version: u8, light: format::frame_light::LightContents) -> format::FrameContents {
        let payload_bits = (light.payload.len() * 8) as u16;
        format::FrameContents {
            preamble: format::preamble::Preamble {
                version,
                flags: light.flags,
                salt: light.salt.unwrap_or([0u8; SALT_LEN]),
                payload_bits,
            },
            payload: light.payload,
        }
    }

    // A light frame at the start of the stream, the common case.
    if let Some(version) = format::frame_light::peek_version(&bits) {
        if version == format::frame_light::VERSION_LIGHT_PLAIN
            || version == format::frame_light::VERSION_LIGHT_SEALED
        {
            let light = format::frame_light::read_light(&bits)?;
            return Ok(from_light(version, light));
        }
    }

    // The heavy frame.
    if let Ok(contents) = format::read(&bits) {
        return Ok(contents);
    }

    // A saturated or excerpted light channel: its first whole frame is not at the
    // start of the stream, so scan for one (SPEC_SATURATE, SAT-CORE-2). The
    // redundancy of saturation is what makes this recover from a fragment.
    if let Some(light) = format::frame_light::scan_light(&bits) {
        let version = if light.salt.is_some() {
            format::frame_light::VERSION_LIGHT_SEALED
        } else {
            format::frame_light::VERSION_LIGHT_PLAIN
        };
        return Ok(from_light(version, light));
    }

    // Nothing readable anywhere; return the heavy reader's named error.
    format::read(&bits)
}

/// Decode a stego text, returning the cascade trace alongside the result.
///
/// This is `decode(trace = true)` of SPEC_CORE_V2 §6.2. The waves run in
/// strict reverse encode order: carriers last-applied first, then the envelope,
/// then the transform chain in reverse. The first wave that cannot keep its
/// promise names itself, halts the chain, and the trace is returned as it
/// stands.
pub fn decode_traced(
    stego_text: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto_methods: &[&dyn CryptoMethod],
    password: Option<&str>,
) -> TracedDecode {
    let mut waves = Vec::new();

    if stego_methods.is_empty() {
        return TracedDecode {
            outcome: Err(SteganoError::InvalidInput(
                "at least one stego method required".into(),
            )),
            waves,
            recovery_mode: false,
        };
    }

    // Wave: carrier identification. A text states nothing about which carriers
    // hold it, so each candidate is asked whether it can find a preamble of
    // its own. This is the one heuristic the cascade is allowed (§6.2), and it
    // decides only *which* chain to drive, never *what* the chain says.
    let started = Instant::now();
    let identified: Vec<&dyn StegoMethod> = stego_methods
        .iter()
        .filter(|method| format::is_framed(&layer_bits(**method, stego_text)))
        .copied()
        .collect();
    waves.push(wave(
        "identify",
        started,
        stego_text.len(),
        identified.len(),
        OracleLevel::Checksum,
        WaveVerdict::Passed,
    ));

    if identified.is_empty() {
        return recover(stego_text, stego_methods, crypto_methods, password, waves);
    }

    // Waves: one per carrier, strict reverse of the order they were applied.
    // Each carrier holds a complete copy of the layer, so the copies must
    // agree; a document where they do not has been altered between them.
    let mut text = stego_text.to_string();
    let mut envelope_bytes: Option<Vec<u8>> = None;
    let mut salt = [0u8; SALT_LEN];

    for method in identified.iter().rev() {
        let started = Instant::now();
        let input = text.len();
        let contents = match read_layer(*method, &text) {
            Ok(contents) => contents,
            Err(e) => {
                waves.push(wave(
                    method.id(),
                    started,
                    input,
                    0,
                    OracleLevel::Checksum,
                    WaveVerdict::Failed {
                        reason: e.to_string(),
                    },
                ));
                return halted(waves, method.id(), e.to_string());
            }
        };

        if let Some(previous) = &envelope_bytes {
            if previous != &contents.payload {
                let reason = format!(
                    "this layer holds {} bytes that differ from the {} bytes the layer above it \
                     holds: the document was altered between them",
                    contents.payload.len(),
                    previous.len()
                );
                waves.push(wave(
                    method.id(),
                    started,
                    input,
                    contents.payload.len(),
                    OracleLevel::Checksum,
                    WaveVerdict::Failed {
                        reason: reason.clone(),
                    },
                ));
                return halted(waves, method.id(), reason);
            }
        }

        waves.push(wave(
            method.id(),
            started,
            input,
            contents.payload.len(),
            OracleLevel::Checksum,
            WaveVerdict::Passed,
        ));

        salt = contents.preamble.salt;
        envelope_bytes = Some(contents.payload);
        // The next carrier down sees the text this one was written into.
        text = method.strip(&text);
    }

    let envelope_bytes = envelope_bytes.expect("an identified carrier always yields a layer");
    let mut detected: Vec<String> = identified
        .iter()
        .map(|method| method.id().to_string())
        .collect();
    detected.dedup();

    // Wave: the envelope itself. Structural, judged by nothing on its own.
    let started = Instant::now();
    let envelope = match Envelope::parse(&envelope_bytes) {
        Ok(envelope) => envelope,
        Err(e) => {
            waves.push(wave(
                "envelope",
                started,
                envelope_bytes.len(),
                0,
                OracleLevel::NotApplicable,
                WaveVerdict::Failed {
                    reason: e.to_string(),
                },
            ));
            return halted(waves, "envelope", e.to_string());
        }
    };
    waves.push(wave(
        "envelope",
        started,
        envelope_bytes.len(),
        envelope.payload.len(),
        OracleLevel::NotApplicable,
        WaveVerdict::Passed,
    ));

    // Waves: the transform chain, in strict reverse order, one per step.
    let mut payload = envelope.payload;
    let mut crypto_used = None;

    for step in envelope.chain.iter().rev() {
        let started = Instant::now();
        let input = payload.len();

        match revert_step(step, &payload, crypto_methods, password, &salt) {
            Ok((reverted, oracle)) => {
                waves.push(wave(
                    &step.id,
                    started,
                    input,
                    reverted.len(),
                    oracle,
                    WaveVerdict::Passed,
                ));
                if step.id != INTEGRITY_STEP {
                    crypto_used = Some(step.id.clone());
                }
                payload = reverted;
            }
            Err((oracle, reason)) => {
                waves.push(wave(
                    &step.id,
                    started,
                    input,
                    0,
                    oracle,
                    WaveVerdict::Failed {
                        reason: reason.clone(),
                    },
                ));
                return halted(waves, &step.id, reason);
            }
        }
    }

    // Integrity is what the exact oracles said, not a separate opinion.
    let integrity_valid = waves.iter().any(|record| {
        record.verdict == WaveVerdict::Passed
            && matches!(record.oracle, OracleLevel::AeadTag | OracleLevel::Checksum)
    });

    TracedDecode {
        outcome: Ok(DecodeResult {
            hidden_data: payload,
            methods_detected: detected,
            crypto_used,
            integrity_valid,
            warnings: Vec::new(),
        }),
        waves,
        recovery_mode: false,
    }
}

/// Revert one chain step, reporting which oracle judged it.
///
/// Returns the reverted bytes and the oracle level on success, or the oracle
/// level and the reason on failure. Nothing here falls back to another step:
/// the chain says what was applied and this reverses exactly that.
fn revert_step(
    step: &ChainStep,
    payload: &[u8],
    crypto_methods: &[&dyn CryptoMethod],
    password: Option<&str>,
    salt: &[u8; SALT_LEN],
) -> std::result::Result<(Vec<u8>, OracleLevel), (OracleLevel, String)> {
    if step.id == INTEGRITY_STEP {
        if payload.len() < CRC32_LEN {
            return Err((
                OracleLevel::Checksum,
                format!(
                    "the integrity step needs {CRC32_LEN} trailing bytes, the layer holds {}",
                    payload.len()
                ),
            ));
        }
        let split = payload.len() - CRC32_LEN;
        let (body, tail) = payload.split_at(split);
        let stored = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
        let computed = crc32(body);
        if stored != computed {
            return Err((
                OracleLevel::Checksum,
                format!("checksum mismatch: stored 0x{stored:08X}, computed 0x{computed:08X}"),
            ));
        }
        return Ok((body.to_vec(), OracleLevel::Checksum));
    }

    // A cipher step. The caller states which ciphers are available to it; a
    // document naming one that is not there is refused rather than guessed at.
    if !crypto_methods.iter().any(|method| method.id() == step.id) {
        return Err((
            OracleLevel::NotApplicable,
            format!(
                "the document names '{}' and that method is not among the ones offered",
                step.id
            ),
        ));
    }

    let password = match password {
        Some(pass) if !pass.is_empty() => pass,
        _ => {
            return Err((
                OracleLevel::NotApplicable,
                format!("the layer is protected by '{}' and no passcode was given", step.id),
            ))
        }
    };

    match keyed_cipher(&step.id) {
        Some(keyed) => {
            // §2 and §6.3: one derivation for the document, then a trial.
            let keys = KeyTree::derive(password, salt).map_err(|e| {
                (
                    OracleLevel::NotApplicable,
                    format!("the key could not be derived: {e}"),
                )
            })?;
            let candidates: [&dyn KeyedCryptoMethod; 1] = [keyed.as_ref()];
            match decrypt_with_candidates(payload, &candidates, &keys) {
                Ok((_, plaintext)) => Ok((plaintext, OracleLevel::AeadTag)),
                Err(e) => Err((OracleLevel::AeadTag, e.to_string())),
            }
        }
        None => {
            // No keyed path yet (backlog F11). It authenticates nothing on its
            // own, which is why the integrity step covers its output.
            let method = crypto_methods
                .iter()
                .find(|method| method.id() == step.id)
                .expect("presence was just checked");
            match method.decrypt(payload, password) {
                Ok(plaintext) => Ok((plaintext, OracleLevel::NotApplicable)),
                Err(e) => Err((OracleLevel::NotApplicable, e.to_string())),
            }
        }
    }
}

/// Build the halted result for a wave that named itself.
fn halted(waves: Vec<WaveRecord>, step: &str, reason: String) -> TracedDecode {
    TracedDecode {
        outcome: Err(SteganoError::DecodingFailed {
            method: step.to_string(),
            reason,
        }),
        waves,
        recovery_mode: false,
    }
}

/// Recovery mode — SPEC_CORE_V2 §6.3, declared and never silent.
///
/// Reached only when no candidate carrier holds a preamble. Every candidate is
/// then swept for a document written before the format existed (§8), which is
/// the one shape that legitimately carries no preamble. The sweep is heuristic
/// by nature, which is exactly why it is confined here, named in the trace and
/// stated in the warnings of anything it returns.
fn recover(
    stego_text: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto_methods: &[&dyn CryptoMethod],
    password: Option<&str>,
    mut waves: Vec<WaveRecord>,
) -> TracedDecode {
    let started = Instant::now();
    let mut tried: Vec<&str> = Vec::new();

    for method in stego_methods {
        tried.push(method.id());
        let Ok(raw) = method.decode(stego_text) else {
            continue;
        };
        let Some(package) = parse_pre_format_package(&raw) else {
            continue;
        };

        let mut warnings = vec![
            "recovery mode: no preamble was found, so the candidate carriers were swept \
             explicitly"
                .to_string(),
            format!(
                "this document was written before the current format and was read through the \
                 pre-format path: carrier '{}', package version {}",
                method.id(),
                package.version
            ),
        ];
        if package.version != PACKAGE_VERSION {
            warnings.push(format!(
                "package version mismatch: expected {PACKAGE_VERSION}, got {}",
                package.version
            ));
        }

        let opened = open_pre_format_package(&package, crypto_methods, password);
        return match opened {
            Ok((plaintext, crypto_used, integrity_valid)) => {
                waves.push(wave(
                    "recovery_sweep",
                    started,
                    stego_text.len(),
                    plaintext.len(),
                    OracleLevel::Checksum,
                    WaveVerdict::Passed,
                ));
                if !integrity_valid {
                    warnings.push("checksum mismatch: data may be corrupted".to_string());
                }
                TracedDecode {
                    outcome: Ok(DecodeResult {
                        hidden_data: plaintext,
                        methods_detected: vec![method.id().to_string()],
                        crypto_used,
                        integrity_valid,
                        warnings,
                    }),
                    waves,
                    recovery_mode: true,
                }
            }
            Err(e) => {
                let reason = e.to_string();
                waves.push(wave(
                    "recovery_sweep",
                    started,
                    stego_text.len(),
                    0,
                    OracleLevel::Checksum,
                    WaveVerdict::Failed {
                        reason: reason.clone(),
                    },
                ));
                TracedDecode {
                    outcome: Err(SteganoError::DecodingFailed {
                        method: "recovery_sweep".into(),
                        reason,
                    }),
                    waves,
                    recovery_mode: true,
                }
            }
        };
    }

    // Nothing found. §6.2 step 5: undetermined, never "failed".
    waves.push(wave(
        "recovery_sweep",
        started,
        stego_text.len(),
        0,
        OracleLevel::NotApplicable,
        WaveVerdict::Undetermined {
            reason: format!(
                "no candidate carrier holds a readable layer: swept {}",
                tried.join(", ")
            ),
        },
    ));

    TracedDecode {
        outcome: Err(SteganoError::NothingDetected),
        waves,
        recovery_mode: true,
    }
}

/// Read a pre-format package out of what a carrier returned.
///
/// A carrier of the pre-format era returned one zero byte per position nothing
/// was ever written to, which is the defect the preamble's `payload_bits`
/// ended. Those trailing bytes are trimmed here, in recovery mode, where a
/// heuristic is declared rather than hidden.
fn parse_pre_format_package(raw: &[u8]) -> Option<DataPackage> {
    let trimmed = match raw.iter().rposition(|byte| *byte != 0) {
        Some(last) => &raw[..=last],
        None => return None,
    };
    let text = std::str::from_utf8(trimmed).ok()?;
    serde_json::from_str::<DataPackage>(text).ok()
}

/// Open a pre-format package: base64, then the cipher it names, then its
/// checksum.
fn open_pre_format_package(
    package: &DataPackage,
    crypto_methods: &[&dyn CryptoMethod],
    password: Option<&str>,
) -> Result<(Vec<u8>, Option<String>, bool)> {
    let payload = B64
        .decode(&package.data)
        .map_err(|_| SteganoError::IntegrityFailed)?;

    let (plaintext, crypto_used) = match &package.crypto {
        Some(crypto_id) => {
            let password = match password {
                Some(pass) if !pass.is_empty() => pass,
                _ => return Err(SteganoError::DecryptionFailed),
            };
            let method = crypto_methods
                .iter()
                .find(|method| method.id() == crypto_id)
                .ok_or_else(|| SteganoError::DecodingFailed {
                    method: crypto_id.clone(),
                    reason: "crypto method not available".into(),
                })?;
            (method.decrypt(&payload, password)?, Some(crypto_id.clone()))
        }
        None => (payload, None),
    };

    let expected = hex::encode(&Sha256::digest(&plaintext)[..4]);
    Ok((plaintext, crypto_used, expected == package.checksum))
}

/// Decode a stego text — SPEC_CORE_V2 §6.2.
///
/// The untraced view of `decode_traced`, kept for callers that only want the
/// result. Every failure still names the wave it stopped at, in the error.
pub fn decode(
    stego_text: &str,
    stego_methods: &[&dyn StegoMethod],
    crypto_methods: &[&dyn CryptoMethod],
    password: Option<&str>,
) -> Result<DecodeResult> {
    decode_traced(stego_text, stego_methods, crypto_methods, password).outcome
}

/// Which carriers leave a trace in this text, and how strong a trace.
pub fn detect(text: &str, methods: &[&dyn StegoMethod]) -> DetectResult {
    let mut detected = Vec::new();

    for method in methods {
        let confidence = method.detect(text);
        if confidence > 0.01 {
            detected.push(DetectedMethod {
                id: method.id().to_string(),
                name: method.name().to_string(),
                confidence,
            });
        }
    }

    let overall = if detected.is_empty() {
        0.0
    } else {
        detected.iter().map(|d| d.confidence).sum::<f64>() / detected.len() as f64
    };

    DetectResult {
        methods: detected,
        overall_confidence: overall,
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ChaCha20;
    use crate::stego::{Homoglyph, ZeroWidth};

    const LONG_ARTICLE: &str = include_str!("../../../tests/corpus/en_long_article.txt");

    fn long_cover() -> &'static str {
        "Access to the open science project expectations are exceptional in scope and practice today across every possible aspect of ecosystem operations including all cooperative joint exercises"
    }

    // ─── Frame mode (COMPOSE-2) ───

    #[test]
    fn the_heavy_frame_round_trips_as_a_selectable_secondary_mode() {
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let secret = b"recovery robust layer";

        let heavy =
            encode_with_frame(LONG_ARTICLE, secret, &methods, None, FrameMode::Heavy).unwrap();
        let back = decode(&heavy.stego_text, &methods, &[], None).unwrap();
        assert_eq!(back.hidden_data, secret, "the heavy frame reads back through decode");

        // The heavy frame's two preamble replicas and markers cost more than the
        // light header, so a cover holds fewer secret bytes under it, and the
        // report says so for each frame.
        let light_cap =
            secret_capacity_bytes_framed(LONG_ARTICLE, &methods, None, FrameMode::Light).unwrap();
        let heavy_cap =
            secret_capacity_bytes_framed(LONG_ARTICLE, &methods, None, FrameMode::Heavy).unwrap();
        assert!(
            heavy_cap < light_cap,
            "heavy capacity {heavy_cap} must be below light {light_cap}"
        );
        assert!(heavy_cap > 0, "but still usable on an ample cover");
    }

    #[test]
    fn the_two_frames_write_different_documents_and_both_read_back() {
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let secret = b"same secret, two frames";

        let light =
            encode_with_frame(LONG_ARTICLE, secret, &methods, None, FrameMode::Light).unwrap();
        let heavy =
            encode_with_frame(LONG_ARTICLE, secret, &methods, None, FrameMode::Heavy).unwrap();
        assert_ne!(
            light.stego_text, heavy.stego_text,
            "the two frames write the same secret differently"
        );
        assert_eq!(
            decode(&light.stego_text, &methods, &[], None).unwrap().hidden_data,
            secret
        );
        assert_eq!(
            decode(&heavy.stego_text, &methods, &[], None).unwrap().hidden_data,
            secret
        );
    }

    #[test]
    fn from_robust_maps_the_toggle_to_the_frame() {
        assert_eq!(FrameMode::from_robust(false), FrameMode::Light);
        assert_eq!(FrameMode::from_robust(true), FrameMode::Heavy);
        assert_eq!(FrameMode::default(), FrameMode::Light);
    }

    // ─── Saturation mode (SAT-CORE-1) ───

    fn zw_channel_chars(text: &str) -> usize {
        text.chars().filter(|c| matches!(*c, '\u{200B}' | '\u{200C}')).count()
    }

    #[test]
    fn saturation_fills_the_channel_and_round_trips() {
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let secret = b"a short mark";

        let plain = encode(LONG_ARTICLE, secret, &methods, None).unwrap();
        let saturated = encode_saturated(LONG_ARTICLE, secret, &methods, None).unwrap();

        // Saturation fills the carrier's channel far past a single framed copy:
        // it is sized to the cover's capacity, not to the secret.
        assert!(
            zw_channel_chars(&saturated.stego_text) > zw_channel_chars(&plain.stego_text) * 2,
            "saturated {} must be far denser than a single copy {}",
            zw_channel_chars(&saturated.stego_text),
            zw_channel_chars(&plain.stego_text)
        );

        // And it still recovers the secret from the first frame.
        let back = decode(&saturated.stego_text, &methods, &[], None).unwrap();
        assert_eq!(back.hidden_data, secret);
    }

    #[test]
    fn saturation_fills_the_cover_to_its_full_capacity() {
        // The honest claim the README states: saturation carries as much as the
        // cover can hold. It fills the carrier's channel to the cover's full
        // position capacity, placing a hidden character at nearly every position
        // the cover offers, stopping only when no further whole copy fits. So the
        // unfilled remainder is always smaller than one single copy, and the fill
        // dwarfs that single copy. Never one copy sized to the secret.
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let secret = b"trace";

        let capacity = zw.positions(LONG_ARTICLE);
        let single = encode(LONG_ARTICLE, secret, &methods, None).unwrap();
        let saturated = encode_saturated(LONG_ARTICLE, secret, &methods, None).unwrap();

        let one_copy = zw_channel_chars(&single.stego_text);
        let placed = zw_channel_chars(&saturated.stego_text);

        // Filled to the cover's capacity, to within less than one further copy.
        assert!(
            capacity - placed < one_copy,
            "saturation left {} of {capacity} positions unfilled, more than one copy ({one_copy})",
            capacity - placed
        );
        // Which is many copies denser than a single placement of the same secret.
        assert!(
            placed >= one_copy * 3,
            "saturation placed {placed}, not far past a single copy {one_copy}"
        );
        // The maximal fill still round-trips the secret.
        let back = decode(&saturated.stego_text, &methods, &[], None).unwrap();
        assert_eq!(back.hidden_data, secret);
    }

    #[test]
    fn saturation_leaves_the_visible_text_identical() {
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let saturated = encode_saturated(LONG_ARTICLE, b"mark", &methods, None).unwrap();
        // Stripping the channel returns the cover exactly: only invisibles were added.
        assert_eq!(zw.strip(&saturated.stego_text), LONG_ARTICLE);
    }

    #[test]
    fn saturation_composes_with_a_cipher() {
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let passcode = "saturate and seal";

        let saturated =
            encode_saturated(LONG_ARTICLE, b"secret under a cipher", &methods, Some((&cc, passcode)))
                .unwrap();
        let back = decode(&saturated.stego_text, &methods, &[&cc], Some(passcode)).unwrap();
        assert_eq!(back.hidden_data, b"secret under a cipher");
        assert!(back.integrity_valid);
    }

    #[test]
    fn saturation_multi_method_recovers() {
        let zw = ZeroWidth::new();
        let ws = crate::stego::WhitespaceVar::new();
        let methods: [&dyn StegoMethod; 2] = [&zw, &ws];
        let secret = b"multi method mark";

        let saturated = encode_saturated(LONG_ARTICLE, secret, &methods, None).unwrap();
        let back = decode(&saturated.stego_text, &methods, &[], None).unwrap();
        assert_eq!(back.hidden_data, secret);
    }

    // ─── Saturation recovery from an excerpt (SAT-CORE-2) ───

    #[test]
    fn a_saturated_document_recovers_from_an_excerpt() {
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let secret = b"survive the cut";
        let saturated = encode_saturated(LONG_ARTICLE, secret, &methods, None).unwrap();

        // Cut the first third away: the surviving channel now begins part way
        // through the stream, so its first whole frame is not at offset zero.
        // The redundancy of saturation plus the frame scan recover it anyway.
        let chars: Vec<char> = saturated.stego_text.chars().collect();
        let excerpt: String = chars[chars.len() / 3..].iter().collect();

        let back = decode(&excerpt, &methods, &[], None).unwrap();
        assert_eq!(back.hidden_data, secret);
    }

    #[test]
    fn a_saturated_encrypted_document_recovers_from_an_excerpt() {
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let methods: [&dyn StegoMethod; 1] = [&zw];
        let passcode = "cut but keyed";
        // A sealed frame carries the salt and the cipher's overhead, so it is much
        // larger than a plain one: the cover must hold several copies for the
        // redundancy to survive a cut, hence a longer cover here.
        let cover = format!("{LONG_ARTICLE} {LONG_ARTICLE} {LONG_ARTICLE}");
        let saturated =
            encode_saturated(&cover, b"keyed and cut", &methods, Some((&cc, passcode))).unwrap();

        let chars: Vec<char> = saturated.stego_text.chars().collect();
        let excerpt: String = chars[chars.len() / 3..].iter().collect();

        let back = decode(&excerpt, &methods, &[&cc], Some(passcode)).unwrap();
        assert_eq!(back.hidden_data, b"keyed and cut");
        assert!(back.integrity_valid);
    }

    // ─── Recommendation engine (COMPOSE-3) ───

    #[test]
    fn a_comfortable_cover_recommends_the_strictest_mission_and_applies() {
        // The long article gives homoglyph ample room, so a short secret hides
        // at Conceal, the most invisible mission. The recommendation says so and
        // it applies: encoding at the recommended mission and carrier places the
        // secret and reads it back.
        let hg = Homoglyph::new();
        let methods: [&dyn StegoMethod; 1] = [&hg];
        let secret = b"north gate at nine";
        let rec = recommend(LONG_ARTICLE, secret, &methods, None).unwrap();

        assert!(rec.fits, "an ample cover must hold a short secret");
        assert_eq!(rec.carrier.as_deref(), Some("homoglyph"));
        assert_eq!(rec.mission.as_deref(), Some("conceal"), "strictest that holds");
        assert_eq!(
            rec.density,
            Some(crate::fidelity::density::ceiling_for(Mission::Conceal))
        );
        assert_eq!(rec.shortfall_bytes, 0);

        let mission = mission_from_lowercase(rec.mission.as_deref().unwrap()).unwrap();
        let placed =
            encode_for_mission(LONG_ARTICLE, secret, &methods, None, Some(mission)).unwrap();
        let back = decode(&placed.stego_text, &methods, &[], None).unwrap();
        assert_eq!(back.hidden_data, secret);
    }

    #[test]
    fn a_load_that_overflows_conceal_is_recommended_a_looser_mission() {
        // A larger secret pushes the fill ratio past Conceal's 0.25 ceiling but
        // stays under Sign's 0.50. The recommendation must step up exactly one
        // mission, to Sign, not straight to Mark, and applying it composes.
        let hg = Homoglyph::new();
        let methods: [&dyn StegoMethod; 1] = [&hg];
        let secret: Vec<u8> = (0..55).map(|i| b'a' + (i % 26) as u8).collect();
        let rec = recommend(LONG_ARTICLE, &secret, &methods, None).unwrap();

        assert!(rec.fits);
        assert_eq!(
            rec.mission.as_deref(),
            Some("sign"),
            "conceal overflows, sign holds, so sign is the strictest that fits"
        );
        let mission = mission_from_lowercase("sign").unwrap();
        assert!(
            encode_for_mission(LONG_ARTICLE, &secret, &methods, None, Some(mission)).is_ok(),
            "the recommended mission must accept the load"
        );
        // And Conceal, the mission it stepped past, must genuinely refuse it.
        assert!(
            encode_for_mission(LONG_ARTICLE, &secret, &methods, None, Some(Mission::Conceal))
                .is_err(),
            "the mission it stepped past must refuse the load"
        );
    }

    #[test]
    fn a_cover_too_small_for_any_mission_recommends_nothing_and_names_the_shortfall() {
        // A short cover cannot hold the load under even Mark. The recommendation
        // refuses to name a carrier, reports the shortfall in bytes, and the
        // engine agrees: encoding refuses.
        let hg = Homoglyph::new();
        let zw = ZeroWidth::new();
        let methods: [&dyn StegoMethod; 2] = [&hg, &zw];
        let cover = "A short line.";
        let secret: Vec<u8> = (0..40).map(|i| b'a' + (i % 26) as u8).collect();
        let rec = recommend(cover, &secret, &methods, None).unwrap();

        assert!(!rec.fits, "nothing holds this load in so short a cover");
        assert_eq!(rec.carrier, None);
        assert_eq!(rec.mission, None);
        assert!(rec.shortfall_bytes > 0, "the shortfall is named, not hidden");
        assert!(
            encode_for_mission(cover, &secret, &[&hg], None, Some(Mission::Mark)).is_err(),
            "the bounded carrier the report named short must refuse the load"
        );
    }

    #[test]
    fn encode_decode_roundtrip_no_crypto() {
        let zw = ZeroWidth::new();
        let cover = long_cover();
        let secret = b"Hello SteganoHero!";

        let encoded = encode(cover, secret, &[&zw], None).unwrap();
        let decoded = decode(&encoded.stego_text, &[&zw], &[], None).unwrap();

        assert_eq!(decoded.hidden_data, secret);
        assert!(decoded.integrity_valid);
        assert!(decoded.crypto_used.is_none());
    }

    #[test]
    fn read_layer_reads_a_light_frame_back_through_a_carrier() {
        // The decode dispatch reads the light frame (the default framing) as well
        // as the heavy one, told apart by the version byte. Written into a real
        // carrier and read back, the payload survives.
        use crate::format::{frame, frame_light, preamble::Flags};
        let zw = ZeroWidth::new();
        let envelope = b"a plain envelope carried light";
        let bits = frame_light::build_light(Flags::conceal(), None, envelope).unwrap();
        let stego = zw
            .encode("A short cover text, deliberately small.", &frame::bits_to_bytes(&bits))
            .unwrap();
        let contents = read_layer(&zw, &stego).unwrap();
        assert_eq!(contents.payload, envelope.to_vec());
        assert_eq!(contents.preamble.version, frame_light::VERSION_LIGHT_PLAIN);
    }

    #[test]
    fn encode_decode_with_crypto() {
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let cover = long_cover();
        let secret = b"Encrypted secret!";
        let password = "strong_password_123";

        let encoded = encode(cover, secret, &[&zw], Some((&cc, password))).unwrap();
        let decoded = decode(
            &encoded.stego_text,
            &[&zw],
            &[&cc],
            Some(password),
        )
        .unwrap();

        assert_eq!(decoded.hidden_data, secret);
        assert!(decoded.integrity_valid);
        assert_eq!(decoded.crypto_used, Some("chacha20_poly1305".into()));
    }

    #[test]
    fn encode_without_password_still_works() {
        // The Python behaviour, kept: an empty password means no cipher.
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let cover = long_cover();
        let secret = b"No password needed";

        // A cipher was offered with an empty password, so nothing encrypts.
        let encoded = encode(cover, secret, &[&zw], Some((&cc, ""))).unwrap();
        let decoded = decode(&encoded.stego_text, &[&zw], &[&cc], None).unwrap();

        assert_eq!(decoded.hidden_data, secret);
        assert!(decoded.crypto_used.is_none());
    }

    #[test]
    fn wrong_password_fails_gracefully() {
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let cover = long_cover();

        let encoded = encode(cover, b"secret", &[&zw], Some((&cc, "right"))).unwrap();
        let result = decode(&encoded.stego_text, &[&zw], &[&cc], Some("wrong"));

        assert!(result.is_err());
    }

    #[test]
    fn detect_finds_zero_width() {
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let cover = long_cover();

        let encoded = encode(cover, b"test", &[&zw], None).unwrap();
        let result = detect(&encoded.stego_text, &[&zw, &hg]);

        assert!(!result.methods.is_empty());
        assert!(result.methods.iter().any(|m| m.id == "zero_width"));
    }

    #[test]
    fn short_cover_overflow_works() {
        // The secret may be longer than the cover: this carrier overflows.
        let zw = ZeroWidth::new();
        let cover = "Hi";
        let secret = b"This is a longer secret than the cover text allows";

        let encoded = encode(cover, secret, &[&zw], None).unwrap();
        let decoded = decode(&encoded.stego_text, &[&zw], &[], None).unwrap();

        assert_eq!(decoded.hidden_data, secret);
    }

    // ─── Mission-gated overflow (backlog F19b) ───

    const EN_SHORT: &str = include_str!("../../../tests/corpus/en_short.txt");

    #[test]
    fn conceal_overflow_on_a_short_cover_refuses_by_named_arithmetic() {
        // The Conceal mission is where invariant 4b is the product, so overflow
        // past the density ceiling is refused rather than written. The refusal
        // carries the arithmetic a caller needs: available is
        // floor(positions * conceal_ceiling / 8) bytes, reported in bits, and
        // needed is the framed payload in bits, which is larger.
        let zw = ZeroWidth::new();
        let secret = b"a payload the short cover cannot conceal";

        let positions = zw.positions(EN_SHORT);
        let ceiling = crate::fidelity::density::ceiling_for(Mission::Conceal);
        let expected_available = ((positions as f64) * ceiling / 8.0).floor() as usize;

        match encode_for_mission(EN_SHORT, secret, &[&zw], None, Some(Mission::Conceal)) {
            Err(SteganoError::CapacityExceeded { needed, available }) => {
                assert_eq!(
                    available,
                    expected_available * 8,
                    "available must be floor(positions * conceal ceiling / 8) bytes, in bits"
                );
                assert!(
                    needed > available,
                    "the payload ({needed} bits) is past the Conceal budget ({available} bits)"
                );
            }
            other => panic!("expected CapacityExceeded, got {other:?}"),
        }
    }

    #[test]
    fn sign_and_mark_allow_the_overflow_and_the_report_matches_the_analysers() {
        // Sign and Mark let the unbounded carrier overflow the cover, and the
        // surface reports the resulting density and the analyser's own verdict
        // rather than refusing. The report must be exactly what metrics and
        // forensic return when asked independently about the produced document.
        let zw = ZeroWidth::new();
        let secret = b"a payload much longer than this short cover can bound without overflow";

        // The carrier really is unbounded on this cover, so this is an overflow.
        assert!(
            !crate::format::cover_bounds_writes(&zw, EN_SHORT),
            "the premise of the test is that this carrier overflows this cover"
        );

        for mission in [Mission::Sign, Mission::Mark] {
            let encoded =
                encode_for_mission(EN_SHORT, secret, &[&zw], None, Some(mission)).unwrap();

            let decoded = decode(&encoded.stego_text, &[&zw], &[], None).unwrap();
            assert_eq!(decoded.hidden_data, secret, "overflow still round-trips");

            let report = overflow_report(&encoded.stego_text);
            assert_eq!(
                report.noise_density,
                crate::metrics::noise_density(&encoded.stego_text),
                "the reported density is the one metrics returns on the result"
            );
            assert_eq!(
                report.verdict,
                crate::forensic::analyze(&encoded.stego_text).verdict.to_string(),
                "the reported verdict is the one forensic returns on the result"
            );
        }
    }

    #[test]
    fn no_mission_overflow_still_works_exactly_as_today() {
        // The zero-breakage guard: "no mission specified" must be today's
        // overflow-allowed behaviour, so the delegating `encode` and an explicit
        // `None` both place a secret longer than the cover, exactly as before.
        let zw = ZeroWidth::new();
        let cover = "Hi";
        let secret = b"This is a longer secret than the cover text allows";

        let via_none = encode_for_mission(cover, secret, &[&zw], None, None).unwrap();
        let via_encode = encode(cover, secret, &[&zw], None).unwrap();

        // The random salt differs per call, so the deterministic figures are
        // what is compared, not the ciphertext.
        assert_eq!(via_none.methods_used, via_encode.methods_used);
        assert_eq!(via_none.capacity_used_bits, via_encode.capacity_used_bits);

        assert_eq!(
            decode(&via_none.stego_text, &[&zw], &[], None)
                .unwrap()
                .hidden_data,
            secret
        );
        assert_eq!(
            decode(&via_encode.stego_text, &[&zw], &[], None)
                .unwrap()
                .hidden_data,
            secret
        );
    }

    // ─── Channel disjointness and composition order (SPEC_CORE_V2 §6.5) ───

    use crate::stego::{Bidi, WhitespaceVar};

    /// Backlog F25: every carrier reports `capacity()` in the same unit, one
    /// payload bit per position. Zero-width used to return eight times that, so
    /// a caller budgeting from `capacity()` handed it eight times the load it
    /// had slots for. Read off the same document, `capacity()` and `positions()`
    /// must agree for each of the four carriers.
    #[test]
    fn every_carrier_reports_capacity_in_payload_bits() {
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let bd = Bidi::new();
        let ws = WhitespaceVar::new();
        let carriers: [&dyn StegoMethod; 4] = [&zw, &hg, &bd, &ws];

        for carrier in carriers {
            let capacity = carrier.capacity(LONG_ARTICLE);
            let positions = carrier.positions(LONG_ARTICLE);
            assert!(
                capacity > 0,
                "{} offers no capacity on the corpus article, so the comparison would be vacuous",
                carrier.id()
            );
            assert_eq!(
                capacity, positions,
                "{} reports capacity in a different unit from its positions",
                carrier.id()
            );
        }
    }

    const ALREADY_CARRYING: &str = include_str!("../../../tests/corpus/already_carrying.txt");

    /// Backlog F20. A cover that already carries a carrier's own alphabet is
    /// refused in one wording, whether reached through the carrier's `encode`
    /// directly or through the multi-carrier compose path. `place_layer` used to
    /// carry a second guard that refused the same situation in different words;
    /// with it gone, the shared `recognition::cover_already_occupied` wording is
    /// the only source.
    ///
    /// Each cover holds a whole byte of its carrier's alphabet, which is the
    /// shape that used to trip the deleted guard: it fired only when the
    /// pre-existing characters decoded to a whole number of bytes, so a partial
    /// byte never reached it. Homoglyph rewrites visible text and never took
    /// that branch, but it must give the same one wording too.
    #[test]
    fn a_cover_already_carrying_is_refused_in_one_wording_on_both_paths() {
        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();
        let bd = Bidi::new();
        let hg = Homoglyph::new();

        // A Latin body long enough for homoglyph to build a frame, plus one
        // whole byte of each carrier's own alphabet appended.
        let carrying_zw = format!("{LONG_ARTICLE}{}", "\u{200B}".repeat(8));
        let carrying_ws = format!("{LONG_ARTICLE}{}", "\u{2060}".repeat(8));
        let carrying_bd = format!("{LONG_ARTICLE}{}", "\u{200E}".repeat(8));
        let carrying_hg = format!("{LONG_ARTICLE}{}", "\u{0435}".repeat(8));

        let cases: [(&dyn StegoMethod, &str); 4] = [
            (&zw, &carrying_zw),
            (&ws, &carrying_ws),
            (&bd, &carrying_bd),
            (&hg, &carrying_hg),
        ];

        for (method, cover) in cases {
            let direct = method
                .encode(cover, b"x")
                .expect_err("the cover already holds this carrier's alphabet")
                .to_string();
            let composed = encode(cover, b"x", &[method], None)
                .expect_err("the compose path must refuse the same cover")
                .to_string();

            assert_eq!(
                direct, composed,
                "{} gives two different refusals for one situation",
                method.id()
            );
            assert!(
                direct.contains("this carrier's alphabet"),
                "{} refusal is not the shared occupancy wording: {direct}",
                method.id()
            );
        }
    }

    /// The corpus document that arrives already carrying is refused in the same
    /// one wording on both paths. It holds the zero-width and whitespace
    /// alphabets (U+200B, U+200C, U+2060, U+FEFF); the fidelity suite pins its
    /// contents to exactly those four invisibles, so bidi and homoglyph are
    /// covered by the constructed covers above rather than by this file.
    #[test]
    fn the_already_carrying_corpus_document_is_refused_in_one_wording() {
        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();

        let carriers: [&dyn StegoMethod; 2] = [&zw, &ws];
        for method in carriers {
            let direct = method
                .encode(ALREADY_CARRYING, b"x")
                .expect_err("the document already holds this carrier's alphabet")
                .to_string();
            let composed = encode(ALREADY_CARRYING, b"x", &[method], None)
                .expect_err("the compose path must refuse the same document")
                .to_string();

            assert_eq!(
                direct, composed,
                "{} gives two different refusals for the corpus document",
                method.id()
            );
            assert!(
                direct.contains("this carrier's alphabet"),
                "{} refusal is not the shared occupancy wording: {direct}",
                method.id()
            );
        }
    }

    /// A carrier that deliberately collides with zero-width's alphabet.
    /// It exists only to prove the composition check rejects overlap: it
    /// carries nothing and says so rather than pretending to succeed.
    use crate::format::PositionChannel;

    struct CollidingCarrier;

    /// It offers no position and says so, which is the honest answer for a
    /// carrier that never carries anything.
    impl PositionChannel for CollidingCarrier {
        fn positions(&self, _text: &str) -> usize {
            0
        }

        fn read_positions(&self, _text: &str) -> Vec<u8> {
            Vec::new()
        }

        fn write_positions(&self, _cover: &str, _bits: &[u8]) -> Result<String> {
            Err(SteganoError::EncodingFailed {
                method: "colliding_test_carrier".into(),
                reason: "test carrier: never carries a payload".into(),
            })
        }
    }

    impl StegoMethod for CollidingCarrier {
        fn id(&self) -> &str {
            "colliding_test_carrier"
        }

        fn name(&self) -> &str {
            "Colliding Test Carrier"
        }

        fn encode(&self, _cover: &str, _payload: &[u8]) -> Result<String> {
            Err(SteganoError::EncodingFailed {
                method: self.id().into(),
                reason: "test carrier: never carries a payload".into(),
            })
        }

        fn decode(&self, _stego: &str) -> Result<Vec<u8>> {
            Err(SteganoError::DecodingFailed {
                method: self.id().into(),
                reason: "test carrier: never carries a payload".into(),
            })
        }

        fn capacity(&self, _cover: &str) -> usize {
            0
        }

        fn detect(&self, _text: &str) -> f64 {
            0.0
        }

        fn strip(&self, text: &str) -> String {
            text.to_string()
        }

        /// U+200B is zero-width's bit 0.
        fn channel(&self) -> &'static [char] {
            &['\u{200B}']
        }
    }

    /// A carrier whose read does not line up with its write.
    ///
    /// It places bits correctly and then reads them back one position late, so
    /// the document it produces is well formed and unreadable. This is the
    /// shape backlog F26 had in the real carriers until it was fixed, and it
    /// is the one thing the up-front capacity ask cannot detect: the cover is
    /// writable and the payload fits, and the pair is still broken.
    struct DriftingCarrier;

    impl DriftingCarrier {
        const ZERO: char = '\u{2063}';
        const ONE: char = '\u{2064}';
        const CHANNEL: [char; 2] = [Self::ZERO, Self::ONE];

        fn is_channel(c: char) -> bool {
            matches!(c, Self::ZERO | Self::ONE)
        }
    }

    impl PositionChannel for DriftingCarrier {
        fn positions(&self, text: &str) -> usize {
            text.chars().filter(|c| !Self::is_channel(*c)).count()
        }

        /// One position late, which is the defect this double exists to carry.
        fn read_positions(&self, text: &str) -> Vec<u8> {
            let all: Vec<u8> = text
                .chars()
                .filter_map(|c| match c {
                    Self::ZERO => Some(0),
                    Self::ONE => Some(1),
                    _ => None,
                })
                .collect();
            all.into_iter().skip(1).collect()
        }

        fn write_positions(&self, cover: &str, bits: &[u8]) -> Result<String> {
            let available = self.positions(cover);
            if bits.len() > available {
                return Err(SteganoError::CapacityExceeded {
                    needed: bits.len(),
                    available,
                });
            }
            let mut out = String::new();
            let mut written = 0usize;
            for ch in cover.chars() {
                out.push(ch);
                if written < bits.len() {
                    out.push(if bits[written] == 1 {
                        Self::ONE
                    } else {
                        Self::ZERO
                    });
                    written += 1;
                }
            }
            Ok(out)
        }
    }

    impl StegoMethod for DriftingCarrier {
        fn id(&self) -> &str {
            "drifting_test_carrier"
        }

        fn name(&self) -> &str {
            "Drifting Test Carrier"
        }

        fn encode(&self, cover: &str, payload: &[u8]) -> Result<String> {
            self.write_positions(cover, &frame::bytes_to_bits(payload))
        }

        fn decode(&self, stego: &str) -> Result<Vec<u8>> {
            let bits = self.read_positions(stego);
            if bits.is_empty() {
                return Err(SteganoError::NothingDetected);
            }
            Ok(frame::bits_to_bytes(&bits))
        }

        fn detect(&self, _text: &str) -> f64 {
            0.0
        }

        fn strip(&self, text: &str) -> String {
            text.chars().filter(|c| !Self::is_channel(*c)).collect()
        }

        fn channel(&self) -> &'static [char] {
            &Self::CHANNEL
        }
    }

    /// The up-front ask says yes and the document is still refused, by name.
    ///
    /// Backlog F19 asked whether the read back in `place_layer` could go now
    /// that capacity is asked for rather than discovered. It cannot: this
    /// carrier passes both up-front questions and produces an unreadable
    /// document, and nothing but the read back notices.
    #[test]
    fn a_carrier_whose_read_disagrees_with_its_write_is_caught_before_the_document_is_returned() {
        let drifting = DriftingCarrier;
        let method: &dyn StegoMethod = &drifting;

        // Both up-front questions answer yes: the cover is writable, and the
        // secret fits with room to spare.
        let room = method
            .framed_capacity_bytes(LONG_ARTICLE)
            .expect("the cover is writable and holds a frame");
        assert!(room > 8, "the cover has room, so size is not the problem");

        match encode(LONG_ARTICLE, b"drift", &[method], None) {
            Err(SteganoError::EncodingFailed { method, reason }) => {
                assert_eq!(method, "drifting_test_carrier");
                assert!(
                    reason.contains("read back"),
                    "the refusal must name what failed: {reason}"
                );
            }
            Ok(_) => panic!("an unreadable document was handed over as a result"),
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    #[test]
    fn real_carriers_have_pairwise_disjoint_channels() {
        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();
        let bd = Bidi::new();
        let hg = Homoglyph::new();
        let carriers: [&dyn StegoMethod; 4] = [&zw, &ws, &bd, &hg];

        for (i, a) in carriers.iter().enumerate() {
            for b in carriers.iter().skip(i + 1) {
                for c in a.channel() {
                    assert!(
                        !b.channel().contains(c),
                        "'{}' and '{}' share U+{:04X}",
                        a.id(),
                        b.id(),
                        *c as u32
                    );
                }
            }
        }
    }

    #[test]
    fn colliding_carrier_is_rejected_at_composition() {
        let zw = ZeroWidth::new();
        let bad = CollidingCarrier;

        match validate_composition(&[&zw, &bad]) {
            Err(SteganoError::ChannelCollision {
                first,
                second,
                codepoint,
            }) => {
                assert_eq!(first, "zero_width");
                assert_eq!(second, "colliding_test_carrier");
                assert_eq!(codepoint, 0x200B);
            }
            other => panic!("expected a channel collision, got {other:?}"),
        }

        // And the pipeline refuses it before touching the cover text.
        let result = encode(long_cover(), b"secret", &[&zw, &bad], None);
        assert!(matches!(
            result,
            Err(SteganoError::ChannelCollision { .. })
        ));
    }

    #[test]
    fn the_same_carrier_twice_is_rejected() {
        let zw = ZeroWidth::new();
        assert!(matches!(
            validate_composition(&[&zw, &zw]),
            Err(SteganoError::ChannelCollision { .. })
        ));
    }

    #[test]
    fn homoglyph_before_another_carrier_is_rejected() {
        let hg = Homoglyph::new();
        let zw = ZeroWidth::new();

        match validate_composition(&[&hg, &zw]) {
            Err(SteganoError::CompositionOrder { carrier, successor }) => {
                assert_eq!(carrier, "homoglyph");
                assert_eq!(successor, "zero_width");
            }
            other => panic!("expected a composition-order rejection, got {other:?}"),
        }

        let result = encode(long_cover(), b"secret", &[&hg, &zw], None);
        assert!(matches!(
            result,
            Err(SteganoError::CompositionOrder { .. })
        ));
    }

    #[test]
    fn the_four_carriers_compose_in_every_legal_order() {
        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();
        let bd = Bidi::new();
        let hg = Homoglyph::new();

        // The three invisible-character carriers do not touch each other's
        // alphabets, so they compose in any order among themselves.
        let invisible: [&dyn StegoMethod; 3] = [&zw, &ws, &bd];
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        for order in orders {
            let chain: Vec<&dyn StegoMethod> = order.iter().map(|&i| invisible[i]).collect();
            assert!(
                validate_composition(&chain).is_ok(),
                "invisible order {order:?} must be legal"
            );

            // Same order with homoglyph appended last.
            let mut with_homoglyph = chain.clone();
            with_homoglyph.push(&hg);
            assert!(
                validate_composition(&with_homoglyph).is_ok(),
                "invisible order {order:?} + homoglyph last must be legal"
            );

            // Homoglyph anywhere but last is not.
            for position in 0..chain.len() {
                let mut illegal = chain.clone();
                illegal.insert(position, &hg);
                assert!(
                    matches!(
                        validate_composition(&illegal),
                        Err(SteganoError::CompositionOrder { .. })
                    ),
                    "homoglyph at position {position} of {order:?} must be rejected"
                );
            }
        }
    }

    #[test]
    fn a_lone_carrier_always_composes() {
        let hg = Homoglyph::new();
        assert!(validate_composition(&[&hg]).is_ok());
    }

    // ─── The frame is wired in (backlog F4) ───

    #[test]
    fn the_checksum_matches_its_published_check_vector() {
        // CRC-32/ISO-HDLC, check value for "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_short_secret_in_a_long_cover_reads_back_exactly() {
        // The defect F2 was built to end, now met through the pipeline: a
        // carrier reading every position it can find used to return the
        // payload followed by one zero byte per unused position.
        let hg = Homoglyph::new();
        let encoded = encode(LONG_ARTICLE, b"Hi", &[&hg], None).unwrap();
        let decoded = decode(&encoded.stego_text, &[&hg], &[], None).unwrap();

        assert_eq!(decoded.hidden_data, b"Hi");
        assert!(decoded.integrity_valid);
    }

    #[test]
    fn every_carrier_round_trips_on_the_long_article() {
        let carriers: [&dyn StegoMethod; 4] = [
            &ZeroWidth::new(),
            &WhitespaceVar::new(),
            &Bidi::new(),
            &Homoglyph::new(),
        ];

        for carrier in carriers {
            let encoded = encode(LONG_ARTICLE, b"one carrier at a time", &[carrier], None)
                .unwrap_or_else(|e| panic!("{} must place: {e}", carrier.id()));
            let decoded = decode(&encoded.stego_text, &[carrier], &[], None)
                .unwrap_or_else(|e| panic!("{} must read back: {e}", carrier.id()));
            assert_eq!(decoded.hidden_data, b"one carrier at a time");
        }
    }

    // ─── Layered composition (SPEC_CORE_V2 §6.5, backlog F10) ───

    #[test]
    fn the_four_carriers_compose_and_round_trip_on_the_long_article() {
        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();
        let bd = Bidi::new();
        let hg = Homoglyph::new();
        let carriers: [&dyn StegoMethod; 4] = [&zw, &ws, &bd, &hg];
        let secret = b"four carriers at once";

        let encoded = encode(LONG_ARTICLE, secret, &carriers, None)
            .expect("all four carriers must compose together");
        assert_eq!(encoded.methods_used.len(), 4);
        assert_eq!(encoded.methods_used.last().unwrap(), "homoglyph");

        // Stripping all four, last applied first, gives the cover back.
        let mut stripped = encoded.stego_text.clone();
        for carrier in carriers.iter().rev() {
            stripped = carrier.strip(&stripped);
        }
        assert_eq!(stripped, LONG_ARTICLE);

        let decoded = decode(&encoded.stego_text, &carriers, &[], None).unwrap();
        assert_eq!(decoded.hidden_data, secret);
        assert_eq!(decoded.methods_detected.len(), 4);

        // Each carrier holds a complete copy of the layer, so any one of them
        // read on its own gives the whole secret back.
        for carrier in carriers {
            let alone = decode(&encoded.stego_text, &[carrier], &[], None)
                .unwrap_or_else(|e| panic!("{} must hold its own copy: {e}", carrier.id()));
            assert_eq!(alone.hidden_data, secret, "carrier {}", carrier.id());
        }
    }

    #[test]
    fn a_carrier_that_was_not_used_is_not_reported_as_present() {
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let all: [&dyn StegoMethod; 2] = [&zw, &hg];

        let encoded = encode(LONG_ARTICLE, b"one layer only", &[&zw], None).unwrap();
        let decoded = decode(&encoded.stego_text, &all, &[], None).unwrap();

        assert_eq!(decoded.methods_detected, vec!["zero_width"]);
        assert_eq!(decoded.hidden_data, b"one layer only");
    }

    // ─── The traced cascade (SPEC_CORE_V2 §6.2, backlog F4) ───

    #[test]
    fn the_trace_holds_one_wave_per_step_in_reverse_encode_order() {
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let carriers: [&dyn StegoMethod; 2] = [&zw, &hg];

        let encoded = encode(LONG_ARTICLE, b"traced", &carriers, None).unwrap();
        let traced = decode_traced(&encoded.stego_text, &carriers, &[], None);

        assert!(traced.outcome.is_ok());
        assert!(!traced.recovery_mode);
        assert_eq!(
            traced.steps(),
            vec!["identify", "homoglyph", "zero_width", "envelope", "crc32"],
            "carriers reverse first, then the envelope, then the chain in reverse"
        );

        for record in &traced.waves {
            assert_eq!(record.verdict, WaveVerdict::Passed, "{}", record.step);
        }

        // Sizes shrink as the layers come off, and every wave is timed.
        let carrier_wave = &traced.waves[1];
        assert!(carrier_wave.input_bytes > carrier_wave.output_bytes);
        assert_eq!(traced.waves[1].oracle, OracleLevel::Checksum);
        assert_eq!(traced.waves.last().unwrap().oracle, OracleLevel::Checksum);
    }

    #[test]
    fn an_encrypted_document_is_judged_by_its_authentication_tag() {
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let passcode = "the trace records the oracle";

        let encoded = encode(LONG_ARTICLE, b"sealed", &[&zw], Some((&cc, passcode))).unwrap();
        let traced = decode_traced(&encoded.stego_text, &[&zw], &[&cc], Some(passcode));

        assert!(traced.outcome.is_ok());
        assert_eq!(
            traced.steps(),
            vec!["identify", "zero_width", "envelope", "chacha20_poly1305"],
            "an AEAD step carries its own tag, so no checksum step is added"
        );
        assert_eq!(traced.waves.last().unwrap().oracle, OracleLevel::AeadTag);
    }

    #[test]
    fn an_encrypted_document_costs_one_key_derivation_to_read() {
        // SPEC_CORE_V2 §2 and §6.3: the salt travels in the preamble, so the
        // reader derives once for the document instead of once per attempt.
        // This is what makes the recovery cost analysis hold.
        use crate::crypto::keytree::argon2_derivation_count;

        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();
        let passcode = "one derivation per document";

        let encoded = encode(LONG_ARTICLE, b"counted", &[&zw], Some((&cc, passcode))).unwrap();

        let before = argon2_derivation_count();
        let decoded = decode(&encoded.stego_text, &[&zw], &[&cc], Some(passcode)).unwrap();
        assert_eq!(argon2_derivation_count() - before, 1);
        assert_eq!(decoded.hidden_data, b"counted");
    }

    #[test]
    fn a_damaged_carrier_in_a_redundant_stack_is_survived_by_the_others() {
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let carriers: [&dyn StegoMethod; 2] = [&zw, &hg];

        let encoded = encode(LONG_ARTICLE, b"halt here", &carriers, None).unwrap();

        // Damage the first substitutable position of the substitution layer,
        // which sits inside its head preamble replica.
        let damaged: String = {
            let mut done = false;
            encoded
                .stego_text
                .chars()
                .map(|c| {
                    if done {
                        return c;
                    }
                    match c {
                        'e' => {
                            done = true;
                            '\u{0435}'
                        }
                        '\u{0435}' => {
                            done = true;
                            'e'
                        }
                        other => other,
                    }
                })
                .collect()
        };
        assert_ne!(damaged, encoded.stego_text, "the test must change something");

        // The light frame is the default: each carrier is a self-contained copy
        // with a minimal header and no second replica. A copy whose header is
        // broken is not recognised as a frame, so the damaged substitution carrier
        // is simply not identified, and the intact zero-width copy still carries
        // the secret. Redundancy survives one damaged carrier, and the output is
        // the exact secret, never a partial or wrong one (invariant 2).
        //
        // (The heavy frame instead identifies the damaged carrier through its
        // surviving replica and halts, naming that wave; that stricter diagnosis
        // is the price of its double preamble and markers, and it stays available
        // as the secondary framing. A corrupt header on its own is refused by name
        // by the frame_light unit tests.)
        let decoded = decode(&damaged, &carriers, &[], None).unwrap();
        assert_eq!(decoded.hidden_data, b"halt here", "the secret survives via the intact carrier");
        assert!(decoded.integrity_valid, "the surviving copy passes its own integrity check");
    }

    #[test]
    fn a_layer_that_disagrees_with_the_one_above_it_halts_the_chain() {
        // Two documents, same carriers, different secrets. Splicing the
        // zero-width layer of one into the other leaves two layers that each
        // read cleanly and say different things. Continuing on that would be
        // choosing one of them, which is inference.
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let carriers: [&dyn StegoMethod; 2] = [&zw, &hg];

        let first = encode(LONG_ARTICLE, b"the first secret", &carriers, None).unwrap();
        let other_layer = encode(LONG_ARTICLE, b"a different one!", &[&zw], None).unwrap();

        // Rebuild the first document with the other document's zero-width bits.
        let mut replacement = other_layer
            .stego_text
            .chars()
            .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}'));
        let spliced: String = first
            .stego_text
            .chars()
            .map(|c| match c {
                '\u{200B}' | '\u{200C}' => replacement.next().unwrap_or(c),
                other => other,
            })
            .collect();

        let traced = decode_traced(&spliced, &carriers, &[], None);
        let failed = traced.failed_wave().expect("disagreeing layers must halt");
        assert_eq!(failed.step, "zero_width");
        assert!(traced.outcome.is_err());
    }

    #[test]
    fn a_protected_layer_with_no_passcode_names_the_wave_it_stopped_at() {
        let zw = ZeroWidth::new();
        let cc = ChaCha20::new();

        let encoded = encode(LONG_ARTICLE, b"sealed", &[&zw], Some((&cc, "a passcode"))).unwrap();
        let traced = decode_traced(&encoded.stego_text, &[&zw], &[&cc], None);

        let failed = traced.failed_wave().expect("a missing passcode must halt");
        assert_eq!(failed.step, "chacha20_poly1305");
        match &failed.verdict {
            WaveVerdict::Failed { reason } => {
                assert!(reason.contains("passcode"), "reason was: {reason}")
            }
            other => panic!("expected a named failure, got {other:?}"),
        }
    }

    // ─── Recovery mode (SPEC_CORE_V2 §6.3) ───

    /// Build a document in the shape this pipeline wrote before the format
    /// landed: a JSON package placed straight through a carrier.
    fn pre_format_document(carrier: &dyn StegoMethod, secret: &[u8]) -> String {
        let checksum = hex::encode(&Sha256::digest(secret)[..4]);
        let package = format!(
            r#"{{"version":"{PACKAGE_VERSION}","data":"{}","crypto":null,"checksum":"{checksum}"}}"#,
            B64.encode(secret)
        );
        carrier.encode(LONG_ARTICLE, package.as_bytes()).unwrap()
    }

    #[test]
    fn a_document_with_no_preamble_is_read_in_recovery_mode_and_says_so() {
        let zw = ZeroWidth::new();
        let hg = Homoglyph::new();
        let all: [&dyn StegoMethod; 2] = [&zw, &hg];

        let document = pre_format_document(&zw, b"written before the format");
        let traced = decode_traced(&document, &all, &[], None);

        assert!(traced.recovery_mode, "recovery mode must be declared");
        assert!(traced.steps().contains(&"recovery_sweep"));
        let recovered = traced.outcome.expect("the pre-format document must read");
        assert_eq!(recovered.hidden_data, b"written before the format");
        assert!(recovered.integrity_valid);
        assert!(
            recovered
                .warnings
                .iter()
                .any(|w| w.contains("recovery mode")),
            "the result must say recovery mode was entered: {:?}",
            recovered.warnings
        );
    }

    #[test]
    fn a_pre_format_document_read_by_a_position_carrier_is_still_recovered() {
        // The substitution carrier returned one zero byte per unused position,
        // which is what made these documents unreadable. Recovery trims them
        // and declares that it did.
        let hg = Homoglyph::new();
        let document = pre_format_document(&hg, b"trailing zeros");
        let traced = decode_traced(&document, &[&hg], &[], None);

        assert!(traced.recovery_mode);
        assert_eq!(
            traced.outcome.expect("must recover").hidden_data,
            b"trailing zeros"
        );
    }

    #[test]
    fn a_full_recovery_sweep_of_a_text_holding_nothing_takes_under_a_second() {
        let zw = ZeroWidth::new();
        let ws = WhitespaceVar::new();
        let bd = Bidi::new();
        let hg = Homoglyph::new();
        let carriers: [&dyn StegoMethod; 4] = [&zw, &ws, &bd, &hg];

        let started = Instant::now();
        let traced = decode_traced(LONG_ARTICLE, &carriers, &[], None);
        let elapsed = started.elapsed();

        assert!(traced.recovery_mode, "the sweep must be declared");
        assert!(
            matches!(traced.outcome, Err(SteganoError::NothingDetected)),
            "an exhausted sweep reports undetermined, never a failure of the document"
        );
        match &traced.waves.last().unwrap().verdict {
            WaveVerdict::Undetermined { reason } => {
                for carrier in ["zero_width", "whitespace_var", "bidi", "homoglyph"] {
                    assert!(reason.contains(carrier), "reason was: {reason}");
                }
            }
            other => panic!("expected an undetermined verdict, got {other:?}"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the full sweep took {elapsed:?}"
        );
    }

    #[test]
    fn a_cover_that_cannot_hold_a_frame_is_refused_by_the_numbers() {
        // No truncation and no partial document: the carrier that cannot fit
        // the frame says how far short the cover is.
        let hg = Homoglyph::new();
        match encode("tiny", b"far too much for this", &[&hg], None) {
            Err(SteganoError::CapacityExceeded { .. }) => {}
            other => panic!("expected CapacityExceeded, got {other:?}"),
        }
    }
}
