#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! SteganoHero desktop application.
//!
//! This binary is the bridge between the interface and `stegano-core`. It owns
//! no algorithm of its own: every carrier, cipher, forensic routine and metric
//! comes from the core crate through its public API.

mod locales;
mod mcp_setup;
mod registry;

#[cfg(test)]
mod guardrails;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use stegano_core::crypto::pqc;
use stegano_core::provenance::{
    self, AiGenerated, Assertion, Binding, DetachedBinding, HumanAuthorship, InBandBinding,
    Integrity, ProvenanceClaim, PublicKeyRef, RecipientFingerprint, Robustness, SignedClaim,
    TrustPolicy,
};
use stegano_core::signing::MasterKeyPair;
use stegano_core::watermark::fingerprint::{self, Recipient};
use stegano_core::sovereignty::{self, MarkClass};
use stegano_core::utils::{Compression, FileEmbed};
use stegano_core::{c2pa_read, forensic, format, metrics, pipeline, traits::StegoMethod};
use stegano_files::{
    clean_file, conceal_file, export_text, extract_text, inspect_file, pristine_file, strip_file,
    supported_targets, target_from_extension, FileFormat,
};
use stegano_mcp::settings::Settings;
use stegano_mcp::tools::{self as mcp_tools, Outcome, SettingsStore};

// ─── Response types ─────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct AppInfo {
    version: String,
    identifier: String,
}

#[derive(Debug, Serialize)]
struct ComposeResponse {
    /// The complete cover text carrying the hidden layer.
    stego_text: String,
    /// Carriers actually applied, in application order.
    carriers_applied: Vec<String>,
    /// Cipher applied to the layer, when one was selected.
    cipher: Option<String>,
    /// True when the secret was sealed to a recipient's public key (post-quantum)
    /// before it was hidden, instead of a passphrase cipher.
    sealed_to_recipient: bool,
    /// Size of the embedded layer.
    layer_bits: usize,
    layer_bytes: usize,
    /// Character counts, so the interface can show that nothing was truncated.
    cover_chars: usize,
    result_chars: usize,
    /// True when stripping every carrier from the result gives the cover text
    /// back exactly. False is a defect and must be shown to the operator.
    cover_restored: bool,
    /// The channel density the tool's own analyser measures on the produced
    /// document, and the summary verdict it reaches. Read straight off the exact
    /// output, so the operator sees what an analyst would, never an estimate.
    /// Compose is permissive (it places, it does not gate on the mission
    /// ceiling), and this is how it stays honest about the result (F19b).
    noise_density: f64,
    verdict: String,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CarrierCapacity {
    id: String,
    /// Raw substitutable positions this carrier reads off the cover text as
    /// typed. Kept for context, but never the figure the interface compares a
    /// payload against: a framed document is larger than the secret it holds.
    bits: usize,
    /// Bytes of secret the compose step will actually accept for this carrier on
    /// the cover as typed. This is the figure the interface shows: ask for this
    /// many and compose takes them, one more is refused with named arithmetic.
    /// From `pipeline::secret_capacity_bytes`, so it cannot drift from encode.
    secret_bytes: usize,
    /// Payload bytes the framed document holds, before the envelope. The meter
    /// measures a layer of a given size against this, in the same unit.
    framed_bytes: usize,
    /// False when the carrier refuses to overflow past `bits`.
    /// True when it accepts a payload larger than its stated capacity.
    accepts_overflow: bool,
    /// True when the cover bounds this carrier, so `secret_bytes` is a limit it
    /// holds itself to. False when it places by extending the document, in which
    /// case the interface shows no fixed limit rather than a misleading number.
    cover_bounds_writes: bool,
    /// Whether this carrier, used on its own, currently gives back what it was
    /// given. Measured at runtime, never assumed. See `carrier_round_trip`.
    round_trip_verified: bool,
}

#[derive(Debug, Serialize)]
struct PayloadSize {
    bits: usize,
    bytes: usize,
}

#[derive(Debug, Serialize)]
struct RevealResponse {
    /// The recovered layer, when it is valid UTF-8 text.
    hidden_text: Option<String>,
    hidden_size_bytes: usize,
    carriers_detected: Vec<String>,
    cipher_used: Option<String>,
    /// True when the recovered payload was opened with a recipient's secret key
    /// (post-quantum), instead of being returned as extracted.
    opened_for_recipient: bool,
    integrity: bool,
    warnings: Vec<String>,
}

/// One wave of the decode cascade, as the interface consumes it.
///
/// This is a flattened view of `pipeline::WaveRecord`: the oracle level and the
/// verdict are lowered to strings the interface branches on, so the trace can be
/// rendered without the interface reaching into the core's enums.
#[derive(Debug, Serialize)]
struct TracedWave {
    /// The core's raw step identifier, kept for the details view only. It is
    /// never turned into a visible label; `category` drives what the reader sees.
    step: String,
    /// The generic role the interface labels this wave with: `identify`,
    /// `carrier`, `envelope`, `confidentiality`, `integrity` or `recovery`.
    category: String,
    /// Which oracle judged this wave: `aead_tag`, `checksum`, `ngram` or `none`.
    oracle: String,
    /// What the wave concluded: `passed`, `failed` or `undetermined`.
    verdict: String,
    /// The reason a wave carries when it failed or was undetermined.
    reason: Option<String>,
    input_bytes: usize,
    output_bytes: usize,
    elapsed_micros: u128,
}

/// A traced reveal: the recovered payload, if any, and the wave trace that shows
/// how the cascade reached it or where it stopped.
#[derive(Debug, Serialize)]
struct TracedRevealResponse {
    /// The recovered payload when it is valid UTF-8 text; absent for a binary
    /// payload, which is reported by size instead.
    hidden_text: Option<String>,
    /// Size of the recovered payload, present when something was recovered.
    hidden_size_bytes: Option<usize>,
    /// True when the cascade recovered a payload.
    recovered: bool,
    /// One record per wave, in the order the cascade ran them, which is strict
    /// reverse of the order the layers were applied.
    waves: Vec<TracedWave>,
    /// The step id of the wave that halted the chain, when one did.
    failed_step: Option<String>,
    /// Carriers that held a readable layer.
    carriers_detected: Vec<String>,
    /// True when an exact oracle (a tag or a checksum) verified the payload.
    integrity: bool,
    /// True when the declared recovery path produced this result.
    recovery_used: bool,
    /// True when a standard pass found no document header and the interface
    /// should offer the declared recovery control, the sweep having not been
    /// authorised by the operator.
    recovery_available: bool,
    /// The error that stopped the cascade, when it stopped for a reason other
    /// than an offered recovery.
    error: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DetectResponse {
    methods: Vec<MethodHit>,
    confidence: f64,
}

#[derive(Debug, Serialize)]
struct MethodHit {
    id: String,
    name: String,
    confidence: f64,
}

#[derive(Debug, Serialize)]
struct MetricsResponse {
    shannon_delta: f64,
    noise_density: f64,
    perplexity_delta: f64,
}

// ─── Shared helpers ─────────────────────────────────────────────

/// Cover text used only to measure how large a composed layer is. Its content
/// is irrelevant: the layer size depends on the payload, not on the cover.
const PROBE_COVER: &str = "probe";

/// Payload used by the round-trip probe.
const PROBE_SECRET: &str = "probe";

/// One sentence, repeated to build a cover text large enough for every
/// carrier's own capacity rule, including the one that needs a substitutable
/// visible position per bit.
const PROBE_SENTENCE: &str =
    "The archive was opened on a quiet morning and every page was counted \
     twice before anyone agreed on what the record actually contained. ";

/// Build the cover text used by the round-trip probe.
fn probe_cover() -> String {
    PROBE_SENTENCE.repeat(24)
}

/// Does this carrier, used on its own, give back what it was given?
///
/// This is measured by composing and revealing a probe, once per carrier per
/// process, rather than declared. A carrier whose read path is broken reports
/// false here and the interface labels it accordingly, so the interface never
/// claims a capability the engine does not currently deliver. When the engine
/// is fixed the label changes on its own.
fn carrier_round_trip(id: &str) -> bool {
    static MEASURED: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = MEASURED.get_or_init(|| Mutex::new(HashMap::new()));

    if let Ok(guard) = cache.lock() {
        if let Some(known) = guard.get(id) {
            return *known;
        }
    }

    let measured = measure_round_trip(id);

    if let Ok(mut guard) = cache.lock() {
        guard.insert(id.to_string(), measured);
    }
    measured
}

fn measure_round_trip(id: &str) -> bool {
    let Ok(method) = registry::carrier(id) else {
        return false;
    };
    let cover = probe_cover();
    let Ok(composed) = pipeline::encode(&cover, PROBE_SECRET.as_bytes(), &[method.as_ref()], None)
    else {
        return false;
    };
    let ciphers = registry::all_ciphers();
    let cipher_refs: Vec<&dyn stegano_core::traits::CryptoMethod> =
        ciphers.iter().map(|b| b.as_ref()).collect();
    match pipeline::decode(&composed.stego_text, &[method.as_ref()], &cipher_refs, None) {
        Ok(result) => result.hidden_data == PROBE_SECRET.as_bytes(),
        Err(_) => false,
    }
}

/// Resolve the crypto selection into the pair the pipeline expects.
///
/// An empty passphrase with a cipher selected is refused rather than silently
/// downgraded to no encryption.
fn crypto_selection(
    cipher_id: Option<&str>,
    password: Option<&str>,
) -> Result<Option<(Box<dyn stegano_core::traits::CryptoMethod>, String)>, String> {
    let Some(id) = cipher_id else {
        return Ok(None);
    };
    if id == registry::CIPHER_NONE {
        return Ok(None);
    }
    let method = registry::cipher(id)?;
    let passphrase = password.unwrap_or("");
    if passphrase.is_empty() {
        return Err(format!(
            "cipher '{id}' was selected but no passphrase was given; \
             the layer would have been embedded unencrypted"
        ));
    }
    Ok(Some((method, passphrase.to_string())))
}

/// Measure whether a carrier accepts a payload larger than its stated
/// capacity. Measured once per process rather than assumed.
fn carrier_accepts_overflow(id: &str) -> bool {
    static MEASURED: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = MEASURED.get_or_init(|| Mutex::new(HashMap::new()));

    if let Ok(guard) = cache.lock() {
        if let Some(known) = guard.get(id) {
            return *known;
        }
    }

    let measured = match registry::carrier(id) {
        Ok(method) => {
            let oversized = vec![b'x'; 64];
            method.capacity(PROBE_COVER) < oversized.len() * 8
                && method.encode(PROBE_COVER, &oversized).is_ok()
        }
        Err(_) => false,
    };

    if let Ok(mut guard) = cache.lock() {
        guard.insert(id.to_string(), measured);
    }
    measured
}

// ─── Commands: application shell ────────────────────────────────

#[tauri::command]
fn app_info(app: tauri::AppHandle) -> AppInfo {
    AppInfo {
        version: app.package_info().version.to_string(),
        identifier: app.config().identifier.clone(),
    }
}

#[tauri::command]
fn locale_environment() -> Result<locales::LocaleEnvironment, String> {
    locales::environment()
}

#[tauri::command]
fn load_locale(code: String) -> Result<std::collections::BTreeMap<String, String>, String> {
    locales::load(&code)
}

#[tauri::command]
fn list_carriers() -> Vec<String> {
    registry::CARRIER_ORDER.iter().map(|s| s.to_string()).collect()
}

#[tauri::command]
fn list_ciphers() -> Vec<String> {
    registry::CIPHER_ORDER.iter().map(|s| s.to_string()).collect()
}

// ─── Commands: compose ──────────────────────────────────────────

/// Place a hidden layer, optionally sealing the secret to a recipient's public
/// key (post-quantum) before placement. The two confidentiality modes are
/// mutually exclusive by construction: the passphrase wrapper passes no recipient
/// key, and the recipient wrapper passes no cipher.
///
/// The recipient seal is applied to the payload BEFORE placement, so the
/// insertion engine sees ordinary bytes and is untouched (invariant 4).
/// Recommend the best carrier, mission and density for hiding a secret in a
/// cover, so the interface can show the advice and, on request, apply it.
///
/// Wraps the frozen core `pipeline::recommend`; it reimplements no capacity or
/// density logic. Every carrier is weighed by default so the best can be
/// suggested even when the operator has not selected it. A cipher is accounted
/// for only once its passcode is present, so the figure never assumes a key the
/// operator has not set; the operator sees the exact result on compose.
#[tauri::command]
fn recommend_settings(
    cover: String,
    secret: String,
    carriers: Vec<String>,
    cipher: Option<String>,
    password: Option<String>,
    robust: bool,
) -> Result<pipeline::Recommendation, String> {
    if secret.is_empty() {
        return Err("nothing to hide: the secret text is empty".to_string());
    }

    let ids: Vec<String> = if carriers.is_empty() {
        registry::CARRIER_ORDER.iter().map(|s| s.to_string()).collect()
    } else {
        registry::normalise_carrier_selection(&carriers)?
    };
    let boxed: Vec<Box<dyn StegoMethod>> = ids
        .iter()
        .map(|id| registry::carrier(id))
        .collect::<Result<_, _>>()?;
    let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();

    let selection = match (cipher.as_deref(), password.as_deref()) {
        (Some(c), Some(p)) if !c.is_empty() && !p.is_empty() => {
            crypto_selection(Some(c), Some(p))?
        }
        _ => None,
    };
    let crypto_pair = selection
        .as_ref()
        .map(|(method, pass)| (method.as_ref(), pass.as_str()));

    let frame_mode = pipeline::FrameMode::from_robust(robust);
    pipeline::recommend_framed(&cover, secret.as_bytes(), &refs, crypto_pair, frame_mode)
        .map_err(|e| e.to_string())
}

fn compose_core(
    cover: String,
    secret: String,
    carriers: Vec<String>,
    cipher: Option<String>,
    password: Option<String>,
    recipient_public_key: Option<String>,
    robust: bool,
    saturate: bool,
) -> Result<ComposeResponse, String> {
    if cover.is_empty() {
        return Err("cover text is empty".to_string());
    }
    if secret.is_empty() {
        return Err("nothing to hide: the secret text is empty".to_string());
    }

    let ordered = registry::normalise_carrier_selection(&carriers)?;
    let boxed: Vec<Box<dyn StegoMethod>> = ordered
        .iter()
        .map(|id| registry::carrier(id))
        .collect::<Result<_, _>>()?;
    let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();

    let selection = crypto_selection(cipher.as_deref(), password.as_deref())?;
    let crypto_pair = selection
        .as_ref()
        .map(|(method, pass)| (method.as_ref(), pass.as_str()));

    // Optional post-quantum recipient sealing, applied to the payload before
    // placement. A malformed key is refused by name, never a silent fallthrough.
    let sealed_to_recipient = recipient_public_key.is_some();
    let payload: Vec<u8> = match &recipient_public_key {
        None => secret.as_bytes().to_vec(),
        Some(public_b64) => {
            let public = B64
                .decode(public_b64.trim())
                .map_err(|_| "the recipient public key is not valid base64".to_string())?;
            pqc::seal(&public, secret.as_bytes()).map_err(|e| e.to_string())?
        }
    };

    // The light frame is the default; the heavy, recovery-robust frame is the
    // opt-in the operator selects with the robust toggle (COMPOSE-2); saturation
    // is the aggressive variant that fills the channel with the secret repeated
    // (SATURATE). encode_composed picks the placement from the two toggles.
    let frame_mode = pipeline::FrameMode::from_robust(robust);
    let result =
        pipeline::encode_composed(&cover, &payload, &refs, crypto_pair, frame_mode, saturate)
            .map_err(|e| e.to_string())?;

    // Stripping every applied carrier must give the cover text back.
    let mut stripped = result.stego_text.clone();
    for method in refs.iter().rev() {
        stripped = method.strip(&stripped);
    }

    // What the tool's own analyser sees on the exact document just produced.
    let report = pipeline::overflow_report(&result.stego_text);

    Ok(ComposeResponse {
        cover_chars: cover.chars().count(),
        result_chars: result.stego_text.chars().count(),
        cover_restored: stripped == cover,
        noise_density: report.noise_density,
        verdict: report.verdict,
        stego_text: result.stego_text,
        carriers_applied: result.methods_used,
        cipher: selection.map(|(method, _)| method.id().to_string()),
        sealed_to_recipient,
        layer_bits: result.capacity_used_bits,
        layer_bytes: result.capacity_used_bits / 8,
        warnings: result.warnings,
    })
}

/// Place a hidden layer, optionally under a passphrase-derived cipher.
#[tauri::command]
fn compose(
    cover: String,
    secret: String,
    carriers: Vec<String>,
    cipher: Option<String>,
    password: Option<String>,
    robust: bool,
    saturate: bool,
) -> Result<ComposeResponse, String> {
    compose_core(cover, secret, carriers, cipher, password, None, robust, saturate)
}

/// Seal a secret to a recipient's public key (post-quantum), then place it. No
/// shared passphrase: only the recipient's secret key opens what is hidden.
#[tauri::command]
fn compose_sealed(
    cover: String,
    secret: String,
    carriers: Vec<String>,
    recipient_public_key: String,
    robust: bool,
    saturate: bool,
) -> Result<ComposeResponse, String> {
    compose_core(cover, secret, carriers, None, None, Some(recipient_public_key), robust, saturate)
}

/// A freshly generated recipient keypair, both halves as base64.
#[derive(Debug, Serialize)]
struct PqcKeypairResponse {
    /// Hand this to senders; they seal secrets to it. Not secret.
    public_key: String,
    /// Keep this private; it opens what was sealed to you.
    secret_key: String,
}

/// Generate a post-quantum recipient keypair (ML-KEM-768). The recipient keeps
/// the secret half and publishes the public half; senders seal to the public
/// half with the recipient mode. This surface keeps neither half.
#[tauri::command]
fn pqc_keypair() -> PqcKeypairResponse {
    let keypair = pqc::generate_keypair();
    PqcKeypairResponse {
        public_key: B64.encode(&keypair.public),
        secret_key: B64.encode(&keypair.secret),
    }
}

/// The canonical output extension for a supported export target.
fn export_extension(format: &FileFormat) -> Option<String> {
    Some(
        match format {
            FileFormat::Markdown => "md",
            FileFormat::Html => "html",
            FileFormat::PlainText => "txt",
            FileFormat::Latex => "tex",
            FileFormat::Rtf => "rtf",
            FileFormat::Org => "org",
            FileFormat::Rst => "rst",
            FileFormat::AsciiDoc => "asciidoc",
            FileFormat::Ipynb => "ipynb",
            FileFormat::Typst => "typ",
            _ => return None,
        }
        .to_string(),
    )
}

/// The export target extensions offered on the desktop, in a stable order. The
/// picker on every result panel is populated from this, so all panels export to
/// the same set.
#[tauri::command]
fn export_formats() -> Vec<String> {
    let mut formats: Vec<String> = supported_targets().iter().filter_map(export_extension).collect();
    // PDF is an export target too, through the self-contained native writer.
    formats.push("pdf".to_string());
    formats
}

/// Export a text result (a marked cover, a revealed secret, a report) to a chosen
/// format, returning the bytes to save. Plain text and Markdown are byte-faithful,
/// so a marked cover's hidden layer survives; the richer targets are a
/// declared-lossy rendering. An unknown target or a writer that cannot keep its
/// promise is refused by name (invariant 2).
#[tauri::command]
fn export_result(text: String, target: String) -> Result<Vec<u8>, String> {
    if text.is_empty() {
        return Err("nothing to export: the result is empty".to_string());
    }
    let format =
        target_from_extension(&target).ok_or_else(|| format!("unknown export target '{target}'"))?;
    export_text(&text, format).map_err(|e| e.to_string())
}

/// The MCP client setup picture: the resolved stegano-mcp command, the universal
/// config snippet, the REST base URL, and every known client with whether it is
/// detected and whether this app can write its config safely.
#[tauri::command]
fn mcp_setup_info() -> mcp_setup::McpSetupInfo {
    let bind = {
        let mut store = settings_store().lock().unwrap();
        read_settings(&mut store)
            .ok()
            .and_then(|value| {
                value
                    .get("server")
                    .and_then(|server| server.get("bind_address"))
                    .and_then(|bind| bind.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "127.0.0.1:3721".to_string())
    };
    mcp_setup::setup_info(&format!("http://{bind}/api/v1"))
}

/// Configure the named clients to use the stegano-mcp server. A writable, detected
/// client has the entry merged into its config after a backup; a snippet client
/// returns its snippet; an undetected client is skipped. Nothing else is touched.
#[tauri::command]
fn mcp_configure(client_ids: Vec<String>) -> Vec<mcp_setup::ConfigureOutcome> {
    let command = mcp_setup::server_command();
    client_ids
        .iter()
        .map(|id| mcp_setup::configure_client(id, &command))
        .collect()
}

/// Extract the readable text from a document file, so any panel can accept a file
/// by resolving it to text before it runs its operation. This is the uniform
/// desktop file input, mirroring the shared resolver on the API. A format that
/// carries no extractable text is refused by name (invariant 2).
#[tauri::command]
fn document_text(bytes: Vec<u8>, format: String) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("no file bytes were provided".to_string());
    }
    let format = file_format_from_string(&format)?;
    extract_text(&bytes, format)
        .map(|extracted| extracted.text)
        .map_err(|e| e.to_string())
}

/// Capacity of every registered carrier against the cover text as typed.
///
/// When several carriers are combined, each one after the first sees the text
/// produced by its predecessor, which is longer. These figures are therefore a
/// lower bound, never an overestimate.
#[tauri::command]
fn carrier_capacity(cover: String, robust: bool) -> Vec<CarrierCapacity> {
    // The reported figures follow the chosen frame (COMPOSE-2): the light default
    // or the heavy, recovery-robust frame, whichever the operator has selected,
    // so the number shown is the one that frame's compose will accept.
    let frame_mode = pipeline::FrameMode::from_robust(robust);
    registry::all_carriers()
        .iter()
        .map(|method| {
            let single: [&dyn StegoMethod; 1] = [method.as_ref()];
            let framed = pipeline::capacity_framed(&cover, &single, None, frame_mode)
                .ok()
                .and_then(|c| c.carriers.into_iter().next());
            CarrierCapacity {
                id: method.id().to_string(),
                bits: method.capacity(&cover),
                // The number shown is the number the encode step will accept.
                secret_bytes: framed.as_ref().map(|c| c.secret_bytes).unwrap_or(0),
                framed_bytes: framed.as_ref().map(|c| c.framed_bytes).unwrap_or(0),
                accepts_overflow: carrier_accepts_overflow(method.id()),
                cover_bounds_writes: format::cover_bounds_writes(method.as_ref(), &cover),
                round_trip_verified: carrier_round_trip(method.id()),
            }
        })
        .collect()
}

/// Check a carrier selection against the core's composition rules before the
/// operator commits to it, so an illegal combination is refused at selection
/// time rather than after the text has been typed.
#[tauri::command]
fn validate_carriers(carriers: Vec<String>) -> Result<Vec<String>, String> {
    let ordered = registry::normalise_carrier_selection(&carriers)?;
    let boxed: Vec<Box<dyn StegoMethod>> = ordered
        .iter()
        .map(|id| registry::carrier(id))
        .collect::<Result<_, _>>()?;
    let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();
    pipeline::validate_composition(&refs).map_err(|e| e.to_string())?;
    Ok(ordered)
}

/// Exact size of the layer that a given secret and cipher would produce.
///
/// This runs the real composition against a throwaway cover text, so the
/// figure is measured rather than estimated. It is a separate command because
/// a passphrase-derived key is deliberately expensive to compute.
#[tauri::command]
fn measure_payload(
    secret: String,
    cipher: Option<String>,
    password: Option<String>,
) -> Result<PayloadSize, String> {
    if secret.is_empty() {
        return Err("nothing to hide: the secret text is empty".to_string());
    }
    let selection = crypto_selection(cipher.as_deref(), password.as_deref())?;
    let crypto_pair = selection
        .as_ref()
        .map(|(method, pass)| (method.as_ref(), pass.as_str()));

    let probe = registry::carrier("zero_width")?;
    let result = pipeline::encode(PROBE_COVER, secret.as_bytes(), &[probe.as_ref()], crypto_pair)
        .map_err(|e| e.to_string())?;

    Ok(PayloadSize {
        bits: result.capacity_used_bits,
        bytes: result.capacity_used_bits / 8,
    })
}

// ─── Commands: mission-gated capacity ───────────────────────────

/// The mission and density enrichment for Compose (backlog UI-mission / E3).
///
/// A mission choice and a fill ratio, resolved against the cover as typed. When
/// a secret is present, the layer is produced under the chosen mission so the
/// interface can show the verdict the tool's own analyser returns on its own
/// output, and the mission's named refusal when the mission will not carry it.
#[derive(Debug, Deserialize)]
struct MissionCapacityRequest {
    cover: String,
    /// The carriers the operator has selected. Empty means "measure against
    /// every carrier", which yields the same narrowest lower bound.
    #[serde(default)]
    carriers: Vec<String>,
    /// Mission id: "conceal", "sign" or "mark".
    mission: String,
    /// The fill ratio the figures are computed at. Absent means the mission's
    /// recommended value, which is what the slider defaults to.
    #[serde(default)]
    density: Option<f64>,
    /// The secret to size the produced-document verdict against, when present.
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// Size against the heavy, recovery-robust frame instead of the light
    /// default when the operator has turned the robust toggle on (COMPOSE-2).
    #[serde(default)]
    robust: bool,
}

#[derive(Debug, Serialize)]
struct MissionCapacityResponse {
    /// The mission id echoed back, so the interface can pair the response with
    /// the control that asked for it.
    mission: String,
    /// The mission's recommended fill ratio, from the core's own `ceiling_for`
    /// (SPEC_CORE_V2 §5.3). The slider defaults here; it never drifts from the
    /// figure the engine's mission gate measures against.
    recommended_density: f64,
    /// The fill ratio the figures below were computed at (the slider value,
    /// clamped to the mission range, defaulting to `recommended_density`).
    density: f64,
    /// The mission's adjustable range endpoints (SPEC_CORE_V2 §5.3).
    min_density: f64,
    max_density: f64,
    /// Substitutable positions the narrowest selected carrier reads off the
    /// cover as typed. The basis of the capacity arithmetic below.
    positions: usize,
    /// `floor(positions * density / 8)`: the fill-ratio budget in secret bytes
    /// (SPEC_CORE_V2 §5.3). The same arithmetic the core's mission gate applies;
    /// the gate stays in the core, this reports the figure so the slider shows a
    /// consequence rather than a bare percentage (SPEC_CORE_V2 §5.4).
    effective_capacity_bytes: usize,
    /// Whether the mission accepted the secret. Present only when a secret was
    /// given: `Some(true)` when it composed, `Some(false)` when the mission
    /// refused it by named arithmetic, `None` when nothing was sized.
    fits: Option<bool>,
    /// The framed layer the secret produces, in bits. Present with a secret.
    needed_bits: Option<usize>,
    /// The mission budget the refusal named, in bits, from the core's own
    /// `CapacityExceeded` arithmetic. Present when the mission refused (F19b).
    available_bits: Option<usize>,
    /// `metrics::noise_density` on the produced document. Present when the
    /// secret composed. Measured on the produced text, never estimated.
    noise_density: Option<f64>,
    /// The verdict `forensic::analyze` returns on the produced document, its
    /// Display form ("CLEAN", "SUSPICIOUS", "MODIFIED", "CONFIRMED"). Present
    /// when the secret composed. Measured, not asserted (SPEC_CORE_V2 §5.4).
    verdict: Option<String>,
}

/// Resolve a mission id from the interface into the core enum. The ids are
/// internal identifiers, never shown to the reader, who sees the localised name.
fn mission_from_id(id: &str) -> Result<format::Mission, String> {
    match id {
        "conceal" => Ok(format::Mission::Conceal),
        "sign" => Ok(format::Mission::Sign),
        "mark" => Ok(format::Mission::Mark),
        other => Err(format!("unknown mission: {other}")),
    }
}

/// The adjustable fill-ratio range for a mission, SPEC_CORE_V2 §5.3. Only the
/// endpoints live here; the recommended value inside the range comes from the
/// core's `ceiling_for`, so the default cannot drift from the gate.
fn mission_density_range(mission: format::Mission) -> (f64, f64) {
    match mission {
        format::Mission::Conceal => (0.05, 0.60),
        format::Mission::Sign => (0.10, 0.90),
        format::Mission::Mark => (0.20, 1.00),
    }
}

/// Report the mission-gated capacity and, when a secret is given, the verdict
/// the tool's own analyser returns on the document that mission would produce.
///
/// This wraps the frozen core and reimplements no gating or density logic: the
/// ceiling and the mission gate belong to `stegano_core`, the density arithmetic
/// is the SPEC_CORE_V2 §5.3 formula the gate itself uses, and the verdict is read
/// straight off `pipeline::overflow_report` on the produced document. A mission
/// that refuses the payload (Conceal overflow, backlog F19b) surfaces the core's
/// own `CapacityExceeded` arithmetic rather than a silent number (invariant 2).
#[tauri::command]
fn mission_capacity(request: MissionCapacityRequest) -> Result<MissionCapacityResponse, String> {
    // An empty cover is not an error here: it offers zero positions, so the
    // figures are zero, and the slider can still initialise from the mission.
    let mission = mission_from_id(&request.mission)?;
    let recommended = stegano_core::fidelity::density::ceiling_for(mission);
    let (min_density, max_density) = mission_density_range(mission);
    let density = request
        .density
        .unwrap_or(recommended)
        .clamp(min_density, max_density);

    // The narrowest carrier bounds the capacity, matching how a stack carries
    // what its narrowest member carries. No selection means every carrier, the
    // same lower bound.
    let carrier_ids: Vec<String> = if request.carriers.is_empty() {
        registry::CARRIER_ORDER.iter().map(|s| s.to_string()).collect()
    } else {
        registry::normalise_carrier_selection(&request.carriers)?
    };
    let boxed: Vec<Box<dyn StegoMethod>> = carrier_ids
        .iter()
        .map(|id| registry::carrier(id))
        .collect::<Result<_, _>>()?;
    let positions = boxed
        .iter()
        .map(|method| method.positions(&request.cover))
        .min()
        .unwrap_or(0);

    // SPEC_CORE_V2 §5.3: capacity_effective = floor(positions * fill_ratio / 8).
    let effective_capacity_bytes = ((positions as f64) * density / 8.0).floor() as usize;

    let mut response = MissionCapacityResponse {
        mission: request.mission.clone(),
        recommended_density: recommended,
        density,
        min_density,
        max_density,
        positions,
        effective_capacity_bytes,
        fits: None,
        needed_bits: None,
        available_bits: None,
        noise_density: None,
        verdict: None,
    };

    // Without a secret, or without a cover to place it in, there is no produced
    // document to judge, so the response carries the capacity figures alone
    // rather than an invented verdict.
    let secret = match request.secret.as_deref() {
        Some(secret) if !secret.is_empty() && !request.cover.is_empty() => secret,
        _ => return Ok(response),
    };

    let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();
    let selection = crypto_selection(request.cipher.as_deref(), request.password.as_deref())?;
    let crypto_pair = selection
        .as_ref()
        .map(|(method, pass)| (method.as_ref(), pass.as_str()));

    // Produce the document under this mission and read back what the tool's own
    // analysers say about it (SPEC_CORE_V2 §5.4). Conceal refuses an overflow
    // payload by named arithmetic (F19b); Sign and Mark allow it and report the
    // density and verdict. The carrier is untouched: the gate lives in the core.
    match pipeline::encode_for_mission_framed(
        &request.cover,
        secret.as_bytes(),
        &refs,
        crypto_pair,
        Some(mission),
        pipeline::FrameMode::from_robust(request.robust),
    ) {
        Ok(result) => {
            let report = pipeline::overflow_report(&result.stego_text);
            response.fits = Some(true);
            response.needed_bits = Some(result.capacity_used_bits);
            response.noise_density = Some(report.noise_density);
            response.verdict = Some(report.verdict);
        }
        Err(stegano_core::SteganoError::CapacityExceeded { needed, available }) => {
            response.fits = Some(false);
            response.needed_bits = Some(needed);
            response.available_bits = Some(available);
        }
        Err(other) => return Err(other.to_string()),
    }

    Ok(response)
}

// ─── Commands: reveal ───────────────────────────────────────────

/// Recover a hidden layer, optionally opening it with a recipient's secret key
/// (post-quantum). The open is applied AFTER extraction; a wrong key or any
/// tampering is refused by name, never a partial result (invariant 2).
fn reveal_core(
    text: String,
    carrier: Option<String>,
    password: Option<String>,
    recipient_secret_key: Option<String>,
) -> Result<RevealResponse, String> {
    if text.is_empty() {
        return Err("the received text is empty".to_string());
    }

    let boxed: Vec<Box<dyn StegoMethod>> = match carrier.as_deref() {
        Some(id) if !id.is_empty() => vec![registry::carrier(id)?],
        _ => registry::all_carriers(),
    };
    let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();

    let ciphers = registry::all_ciphers();
    let cipher_refs: Vec<&dyn stegano_core::traits::CryptoMethod> =
        ciphers.iter().map(|b| b.as_ref()).collect();

    let result = pipeline::decode(&text, &refs, &cipher_refs, password.as_deref())
        .map_err(|e| e.to_string())?;

    // Optional post-quantum recipient opening, applied after extraction.
    let opened_for_recipient = recipient_secret_key.is_some();
    let revealed: Vec<u8> = match &recipient_secret_key {
        None => result.hidden_data,
        Some(secret_b64) => {
            let secret = B64
                .decode(secret_b64.trim())
                .map_err(|_| "the recipient secret key is not valid base64".to_string())?;
            pqc::open(&secret, &result.hidden_data).map_err(|e| e.to_string())?
        }
    };

    let hidden_size_bytes = revealed.len();
    let hidden_text = String::from_utf8(revealed).ok();

    Ok(RevealResponse {
        hidden_text,
        hidden_size_bytes,
        carriers_detected: result.methods_detected,
        cipher_used: result.crypto_used,
        opened_for_recipient,
        integrity: result.integrity_valid,
        warnings: result.warnings,
    })
}

/// Recover a hidden layer, optionally under a passphrase-derived cipher.
#[tauri::command]
fn reveal(
    text: String,
    carrier: Option<String>,
    password: Option<String>,
) -> Result<RevealResponse, String> {
    reveal_core(text, carrier, password, None)
}

/// Recover a hidden layer and open it with your secret key (post-quantum),
/// when the secret was sealed to you. A wrong key is refused by name.
#[tauri::command]
fn reveal_sealed(
    text: String,
    carrier: Option<String>,
    recipient_secret_key: String,
) -> Result<RevealResponse, String> {
    reveal_core(text, carrier, None, Some(recipient_secret_key))
}

// ─── Commands: traced reveal ────────────────────────────────────

/// The generic role the interface labels a wave with. The concrete carrier or
/// cipher identifier is never turned into a visible label: the trace names what
/// the reader sees (a layer, an envelope, a verdict), never how a layer is
/// placed. `crc32` is the core's stable identifier for the integrity step.
fn wave_category(step: &str) -> &'static str {
    match step {
        "identify" => "identify",
        "envelope" => "envelope",
        "recovery_sweep" => "recovery",
        "crc32" => "integrity",
        other => {
            if registry::carrier(other).is_ok() {
                "carrier"
            } else {
                "confidentiality"
            }
        }
    }
}

/// Lower one core wave record onto the interface's serialisable shape.
fn map_wave(record: &pipeline::WaveRecord) -> TracedWave {
    let oracle = match record.oracle {
        pipeline::OracleLevel::AeadTag => "aead_tag",
        pipeline::OracleLevel::Checksum => "checksum",
        pipeline::OracleLevel::NGram => "ngram",
        pipeline::OracleLevel::NotApplicable => "none",
    };
    let (verdict, reason) = match &record.verdict {
        pipeline::WaveVerdict::Passed => ("passed", None),
        pipeline::WaveVerdict::Failed { reason } => ("failed", Some(reason.clone())),
        pipeline::WaveVerdict::Undetermined { reason } => ("undetermined", Some(reason.clone())),
    };
    TracedWave {
        category: wave_category(&record.step).to_string(),
        step: record.step.clone(),
        oracle: oracle.to_string(),
        verdict: verdict.to_string(),
        reason,
        input_bytes: record.input_bytes,
        output_bytes: record.output_bytes,
        elapsed_micros: record.elapsed_micros,
    }
}

/// Reveal a payload and return the wave trace that recovered it, or that shows
/// where the cascade stopped.
///
/// This wraps `pipeline::decode_traced` and reimplements none of the cascade:
/// the layers are reverted in strict reverse order, one wave per layer, and the
/// first wave that cannot keep its promise names itself.
///
/// Recovery is a declared mode, never an automatic fallback. When a standard
/// pass finds no document header, the core probes its bounded legacy path; this
/// command does not surface that path's outcome unless the operator authorised
/// it with `recovery`. Authorising recovery lets its result be read; it does not
/// force recovery when a standard pass already succeeds.
#[tauri::command]
fn reveal_traced(
    text: String,
    password: Option<String>,
    recovery: bool,
) -> Result<TracedRevealResponse, String> {
    if text.trim().is_empty() {
        return Err("the received text is empty".to_string());
    }

    let carriers = registry::all_carriers();
    let carrier_refs: Vec<&dyn StegoMethod> = carriers.iter().map(|b| b.as_ref()).collect();
    let ciphers = registry::all_ciphers();
    let cipher_refs: Vec<&dyn stegano_core::traits::CryptoMethod> =
        ciphers.iter().map(|b| b.as_ref()).collect();

    let pipeline::TracedDecode {
        outcome,
        waves: raw_waves,
        recovery_mode,
    } = pipeline::decode_traced(&text, &carrier_refs, &cipher_refs, password.as_deref());

    // A standard pass found no header. The core has already probed its bounded
    // legacy path, but the operator has not authorised recovery, so its outcome
    // is not surfaced: the interface offers the declared recovery control, and
    // the recovery sweep is kept out of the standard-mode trace.
    if recovery_mode && !recovery {
        let waves = raw_waves
            .iter()
            .filter(|record| record.step != "recovery_sweep")
            .map(map_wave)
            .collect();
        return Ok(TracedRevealResponse {
            hidden_text: None,
            hidden_size_bytes: None,
            recovered: false,
            waves,
            failed_step: None,
            carriers_detected: Vec::new(),
            integrity: false,
            recovery_used: false,
            recovery_available: true,
            error: None,
            warnings: Vec::new(),
        });
    }

    let failed_step = raw_waves
        .iter()
        .find(|record| record.is_failure())
        .map(|record| record.step.clone());
    let waves: Vec<TracedWave> = raw_waves.iter().map(map_wave).collect();

    match outcome {
        Ok(result) => {
            let hidden_size_bytes = result.hidden_data.len();
            let hidden_text = String::from_utf8(result.hidden_data).ok();
            Ok(TracedRevealResponse {
                hidden_text,
                hidden_size_bytes: Some(hidden_size_bytes),
                recovered: true,
                waves,
                failed_step,
                carriers_detected: result.methods_detected,
                integrity: result.integrity_valid,
                recovery_used: recovery_mode,
                recovery_available: false,
                error: None,
                warnings: result.warnings,
            })
        }
        Err(error) => Ok(TracedRevealResponse {
            hidden_text: None,
            hidden_size_bytes: None,
            recovered: false,
            waves,
            failed_step,
            carriers_detected: Vec::new(),
            integrity: false,
            recovery_used: recovery_mode,
            recovery_available: false,
            error: Some(error.to_string()),
            warnings: Vec::new(),
        }),
    }
}

// ─── Commands: inspect ──────────────────────────────────────────

#[tauri::command]
fn forensic_analyze(text: String) -> Result<forensic::ForensicReport, String> {
    if text.is_empty() {
        return Err("the text to inspect is empty".to_string());
    }
    Ok(forensic::analyze(&text))
}

#[tauri::command]
fn detect(text: String) -> DetectResponse {
    let all = registry::all_carriers();
    let refs: Vec<&dyn StegoMethod> = all.iter().map(|b| b.as_ref()).collect();
    let result = pipeline::detect(&text, &refs);

    DetectResponse {
        methods: result
            .methods
            .into_iter()
            .map(|m| MethodHit {
                id: m.id,
                name: m.name,
                confidence: m.confidence,
            })
            .collect(),
        confidence: result.overall_confidence,
    }
}

#[tauri::command]
fn compute_metrics(original: String, candidate: String) -> Result<MetricsResponse, String> {
    if original.is_empty() || candidate.is_empty() {
        return Err("both texts are required to compare them".to_string());
    }
    let m = metrics::compute_metrics(&original, &candidate);
    // `survival_score` is not reported: the core returns a fixed 0.0 for it,
    // so showing it would present an unimplemented metric as a measurement.
    Ok(MetricsResponse {
        shannon_delta: m.shannon_delta,
        noise_density: m.noise_density,
        perplexity_delta: m.perplexity_delta,
    })
}

#[tauri::command]
fn strip_carriers(text: String, carrier: Option<String>) -> Result<String, String> {
    let boxed: Vec<Box<dyn StegoMethod>> = match carrier.as_deref() {
        Some(id) if !id.is_empty() => vec![registry::carrier(id)?],
        _ => registry::all_carriers(),
    };
    let mut current = text;
    for method in boxed.iter().rev() {
        current = method.strip(&current);
    }
    Ok(current)
}

// ─── Provenance ─────────────────────────────────────────────────
//
// These commands wrap the frozen `stegano_core::provenance` API. They own no
// signing or verification logic of their own: they assemble the assertions and
// binding the operator chose, hand them to the core, and report exactly what the
// core returned. A private key is read from the request, used, and never logged.

/// Local hex helpers, kept in this crate so it adds no dependency for them.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Err("the hex value is empty".to_string());
    }
    if hex.len() % 2 != 0 {
        return Err("the hex value has an odd number of digits".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| "the hex value contains a non-hex digit".to_string())
        })
        .collect()
}

/// Trim an optional string, folding an all-whitespace value to `None` so an
/// empty interface field never becomes a present-but-blank assertion payload.
fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// A newly minted Ed25519 signing identity. The private key is returned once so
/// the operator can copy it deliberately; it is never persisted or logged.
#[derive(Debug, Serialize)]
struct SigningIdentity {
    algorithm: String,
    public_key: String,
    private_key: String,
}

/// The assertions an operator ticked, with their optional fields.
#[derive(Debug, Default, Deserialize)]
struct AssertionSelection {
    #[serde(default)]
    human_authorship: bool,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    ai_generated: bool,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    system_version: Option<String>,
    #[serde(default)]
    integrity: bool,
    #[serde(default)]
    recipient_fingerprint: bool,
    #[serde(default)]
    recipient_id: Option<String>,
    #[serde(default)]
    recipient_salt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MarkRequest {
    cover: String,
    assertions: AssertionSelection,
    private_key: String,
    /// "detached" or "in_band".
    binding: String,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    created: Option<String>,
}

#[derive(Debug, Serialize)]
struct MarkResponse {
    binding: String,
    /// The detached sidecar JSON, when the detached binding was chosen.
    sidecar: Option<String>,
    /// The document carrying the mark, when the in-band binding was chosen.
    marked_text: Option<String>,
    /// Whether stripping the carrier returns the cover exactly (in-band only).
    cover_restored: Option<bool>,
    /// The robustness the binding declares before the document is measured.
    declared_robustness: Robustness,
    /// The robustness measured on the produced document (in-band only).
    measured_robustness: Option<Robustness>,
    /// The signer's public key, hex. Safe to show and to distribute.
    signer_public_key: String,
    assertion_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    document: String,
    #[serde(default)]
    sidecar: Option<String>,
    #[serde(default)]
    trusted_keys: Vec<String>,
    /// Carriers to attempt an in-band read through.
    #[serde(default)]
    carriers: Vec<String>,
}

/// Rebuild a keypair from a hex private key, naming a wrong length by size.
fn keypair_from_private(private_key: &str) -> Result<MasterKeyPair, String> {
    let bytes = hex_decode(private_key)?;
    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!("a signing key must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(MasterKeyPair::from_private_bytes(&array))
}

/// Assemble the typed assertions the operator selected over `cover`. Refuses an
/// empty set by name and surfaces the core's own refusals (an unfingerprintable
/// cover, for instance) rather than degrading them.
fn build_assertions(
    cover: &str,
    selection: &AssertionSelection,
) -> Result<Vec<Box<dyn Assertion>>, String> {
    let mut owned: Vec<Box<dyn Assertion>> = Vec::new();

    if selection.human_authorship {
        owned.push(Box::new(HumanAuthorship {
            author: non_empty(selection.author.clone()),
        }));
    }
    if selection.ai_generated {
        owned.push(Box::new(AiGenerated {
            model: non_empty(selection.model.clone()),
            provider: non_empty(selection.provider.clone()),
            system_version: non_empty(selection.system_version.clone()),
        }));
    }
    if selection.integrity {
        let document_hash =
            stegano_core::license::document_hash(cover).map_err(|e| e.to_string())?;
        owned.push(Box::new(Integrity { document_hash }));
    }
    if selection.recipient_fingerprint {
        let recipient_id = non_empty(selection.recipient_id.clone()).ok_or_else(|| {
            "a recipient fingerprint assertion needs a recipient identifier".to_string()
        })?;
        let salt = selection.recipient_salt.clone().unwrap_or_default();
        let fingerprint =
            RecipientFingerprint::derive(&recipient_id, &salt, cover).map_err(|e| e.to_string())?;
        owned.push(Box::new(fingerprint));
    }

    if owned.is_empty() {
        return Err("a provenance claim needs at least one assertion".to_string());
    }
    Ok(owned)
}

/// Mint a fresh Ed25519 signing identity through the core's `signing` module.
///
/// The private key rides back once so the operator can copy it deliberately.
/// Nothing here writes it to disk or to a log.
#[tauri::command]
fn generate_signing_identity() -> SigningIdentity {
    let keypair = MasterKeyPair::generate();
    let public = keypair.public_key();
    SigningIdentity {
        algorithm: "ed25519".to_string(),
        public_key: hex_encode(&public.to_bytes()),
        private_key: hex_encode(&keypair.private_bytes()),
    }
}

/// Attach a signed provenance claim to a document, through the chosen binding.
///
/// The signing key is used and dropped; it is never returned, persisted or
/// logged. A cover too small for an in-band claim surfaces the core's named
/// capacity refusal rather than a truncated result.
#[tauri::command]
fn provenance_mark(request: MarkRequest) -> Result<MarkResponse, String> {
    if request.cover.trim().is_empty() {
        return Err("the document to mark is empty".to_string());
    }

    let keypair = keypair_from_private(&request.private_key)?;
    let public = keypair.public_key();
    let signer_public_key = hex_encode(&public.to_bytes());

    let owned = build_assertions(&request.cover, &request.assertions)?;
    let refs: Vec<&dyn Assertion> = owned.iter().map(|b| b.as_ref()).collect();

    let claim = ProvenanceClaim::new(
        &refs,
        &request.cover,
        &public,
        non_empty(request.created.clone()),
    )
    .map_err(|e| e.to_string())?;
    let assertion_kinds: Vec<String> = claim.assertions.iter().map(|a| a.kind.clone()).collect();
    let signed = SignedClaim::sign(claim, &keypair).map_err(|e| e.to_string())?;

    match request.binding.as_str() {
        "detached" => {
            let binding = DetachedBinding::new();
            let output = binding
                .bind(&request.cover, &signed)
                .map_err(|e| e.to_string())?;
            let sidecar = String::from_utf8(output.bytes)
                .map_err(|_| "the sidecar is not valid UTF-8".to_string())?;
            Ok(MarkResponse {
                binding: "detached".to_string(),
                sidecar: Some(sidecar),
                marked_text: None,
                cover_restored: None,
                declared_robustness: binding.declared_robustness(),
                measured_robustness: None,
                signer_public_key,
                assertion_kinds,
            })
        }
        "in_band" => {
            let carrier_id = non_empty(request.carrier.clone())
                .ok_or_else(|| "an in-band binding needs a carrier".to_string())?;
            let method = registry::carrier(&carrier_id)?;
            let binding = InBandBinding::new(method.as_ref());
            let output = binding
                .bind(&request.cover, &signed)
                .map_err(|e| e.to_string())?;
            let marked_text = String::from_utf8(output.bytes)
                .map_err(|_| "the marked text is not valid UTF-8".to_string())?;
            let cover_restored = method.strip(&marked_text) == request.cover;
            let measured = binding.realised_robustness(&marked_text);
            Ok(MarkResponse {
                binding: "in_band".to_string(),
                sidecar: None,
                marked_text: Some(marked_text),
                cover_restored: Some(cover_restored),
                declared_robustness: binding.declared_robustness(),
                measured_robustness: Some(measured),
                signer_public_key,
                assertion_kinds,
            })
        }
        other => Err(format!("unknown binding: {other}")),
    }
}

/// Verify a received document against an optional sidecar and a set of trusted
/// keys, reading in-band claims through the carriers offered.
///
/// The report is the core's own: a present-but-invalid claim stays present and
/// named, an altered document is reported altered, an absent binding is absent.
#[tauri::command]
fn provenance_verify(request: VerifyRequest) -> Result<provenance::ProvenanceReport, String> {
    if request.document.trim().is_empty() {
        return Err("the document to verify is empty".to_string());
    }

    // Trusted keys: validate each is a real Ed25519 key so a typo is named here
    // rather than quietly failing to match any signer.
    let mut trusted: Vec<PublicKeyRef> = Vec::new();
    for key in &request.trusted_keys {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            continue;
        }
        let reference = PublicKeyRef {
            alg: "ed25519".to_string(),
            key: trimmed.to_string(),
        };
        reference.to_public_key().map_err(|e| e.to_string())?;
        trusted.push(reference);
    }
    let policy = TrustPolicy::new(trusted);

    // Carriers to attempt an in-band read through.
    let mut boxed: Vec<Box<dyn StegoMethod>> = Vec::new();
    for id in &request.carriers {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            continue;
        }
        boxed.push(registry::carrier(trimmed)?);
    }
    let method_refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();

    // An empty or all-whitespace sidecar is absent, not a corrupt sidecar.
    let sidecar_bytes = match request.sidecar.as_ref() {
        Some(sidecar) if !sidecar.trim().is_empty() => Some(sidecar.as_bytes()),
        _ => None,
    };

    provenance::verify_document(&request.document, sidecar_bytes, &method_refs, &policy)
        .map_err(|e| e.to_string())
}

// ─── Canary trap ────────────────────────────────────────────────

/// The registry an operator saves after a canary generation and pastes back to
/// trace a leak. It holds exactly what `identify_leak` needs: the recipients
/// and their assigned fingerprints. It is its own JSON document so the operator
/// can keep it in a file of their own choosing, beside the copies they issued.
#[derive(Debug, Serialize, Deserialize)]
struct CanaryRegistry {
    /// The per-document salt the fingerprints were derived from.
    salt: String,
    /// Bits of fingerprint the document could carry.
    fingerprint_bits: usize,
    /// One entry per recipient, each carrying its assigned fingerprint.
    recipients: Vec<Recipient>,
}

#[derive(Debug, Deserialize)]
struct CanaryGenerateRequest {
    document: String,
    /// One recipient identifier per entry, already split by the interface.
    recipients: Vec<String>,
    salt: String,
}

/// A single marked version as the interface shows it: the recipient, the
/// fingerprint that identifies it, and the marked text to hand to that
/// recipient. Visually identical to the document, provably so.
#[derive(Debug, Serialize)]
struct CanaryVersionView {
    recipient_id: String,
    fingerprint_hex: String,
    text: String,
}

#[derive(Debug, Serialize)]
struct CanaryGenerateResponse {
    versions: Vec<CanaryVersionView>,
    recipient_count: usize,
    fingerprint_bits: usize,
    /// True when every version strips back to the exact document, so all copies
    /// look identical to the cover. False is a defect and is shown as one.
    cover_restored: bool,
    /// The registry JSON to save. Paste it back into Trace to identify a leak.
    registry: String,
}

#[derive(Debug, Deserialize)]
struct CanaryTraceRequest {
    leaked_text: String,
    registry: String,
}

#[derive(Debug, Serialize)]
struct CanaryTraceResponse {
    /// The recipient a leaked copy is traced to, when one in the registry
    /// matches. Absent when nothing matches: this is never a guessed name.
    matched_recipient: Option<String>,
    /// The confidence the engine returns for this identification.
    confidence: f64,
    /// The fingerprint read out of the leaked text, hex. On a match it equals
    /// the matched version's fingerprint exactly.
    extracted_fingerprint_hex: String,
    /// How many recipients the registry held, for context.
    recipient_count: usize,
}

/// Generate one visually identical marked copy per recipient, plus the registry
/// that later traces a leak. Wraps `watermark::fingerprint::generate_batch`; it
/// owns no marking logic of its own.
///
/// A document with nothing to mark, or an empty recipient list, surfaces a named
/// refusal rather than a silent empty result.
#[tauri::command]
fn canary_generate(request: CanaryGenerateRequest) -> Result<CanaryGenerateResponse, String> {
    if request.document.trim().is_empty() {
        return Err("the document to mark is empty".to_string());
    }
    let recipients: Vec<String> = request
        .recipients
        .iter()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    if recipients.is_empty() {
        return Err("name at least one recipient".to_string());
    }
    let recipient_refs: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();

    let batch = fingerprint::generate_batch(&request.document, &recipient_refs, &request.salt)
        .map_err(|e| e.to_string())?;

    // Prove every version strips back to the exact document, so all the copies
    // look identical to the cover. Measured on the produced text, not assumed.
    let stripper = registry::carrier("homoglyph")?;
    let cover_restored = batch
        .versions
        .iter()
        .all(|version| stripper.strip(&version.text) == request.document);

    let versions: Vec<CanaryVersionView> = batch
        .versions
        .iter()
        .map(|version| CanaryVersionView {
            recipient_id: version.recipient.id.clone(),
            fingerprint_hex: hex_encode(&version.recipient.fingerprint),
            text: version.text.clone(),
        })
        .collect();

    let registry_document = CanaryRegistry {
        salt: request.salt.clone(),
        fingerprint_bits: batch.fingerprint_bits,
        recipients: batch
            .versions
            .iter()
            .map(|version| version.recipient.clone())
            .collect(),
    };
    let registry = serde_json::to_string_pretty(&registry_document)
        .map_err(|e| format!("the registry could not be written: {e}"))?;

    Ok(CanaryGenerateResponse {
        recipient_count: versions.len(),
        fingerprint_bits: batch.fingerprint_bits,
        cover_restored,
        versions,
        registry,
    })
}

/// Identify which recipient a leaked copy came from, using the registry saved at
/// generation time. Wraps `watermark::fingerprint::identify_leak`.
///
/// No match is reported as no match. The command never returns a recipient the
/// engine did not identify.
#[tauri::command]
fn canary_trace(request: CanaryTraceRequest) -> Result<CanaryTraceResponse, String> {
    if request.leaked_text.trim().is_empty() {
        return Err("the leaked text to trace is empty".to_string());
    }
    if request.registry.trim().is_empty() {
        return Err("paste the registry saved when the copies were generated".to_string());
    }
    let registry: CanaryRegistry = serde_json::from_str(&request.registry)
        .map_err(|e| format!("the registry is not a readable canary registry: {e}"))?;
    if registry.recipients.is_empty() {
        return Err("the registry holds no recipients".to_string());
    }

    let outcome = fingerprint::identify_leak(&request.leaked_text, &registry.recipients)
        .map_err(|e| e.to_string())?;

    Ok(CanaryTraceResponse {
        matched_recipient: outcome.recipient.map(|recipient| recipient.id),
        confidence: outcome.confidence,
        extracted_fingerprint_hex: hex_encode(&outcome.extracted_fingerprint),
        recipient_count: registry.recipients.len(),
    })
}

// ─── AI-regulation ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DocumentInspectRequest {
    document: String,
}

#[derive(Debug, Deserialize)]
struct DocumentCleanRequest {
    document: String,
    /// Class ids to remove. Empty means every removable class, matching the
    /// other surfaces' default.
    classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DocumentPristineRequest {
    document: String,
}

#[derive(Debug, Deserialize)]
struct C2paInspectRequest {
    /// The file's raw bytes, read by the interface from a file or a paste.
    bytes: Vec<u8>,
    /// A filename or MIME hint, so the reader can pick the container format.
    format_hint: Option<String>,
}

/// Inspect a document and report every mark this tool can see. Wraps
/// `sovereignty::inspect`; it reimplements no detection of its own.
///
/// This is a person asking what is on their own document, not defeating another
/// party's detector. An empty document is a named refusal.
#[tauri::command]
fn document_inspect(
    request: DocumentInspectRequest,
) -> Result<sovereignty::InspectionReport, String> {
    if request.document.is_empty() {
        return Err("the document to inspect is empty".to_string());
    }
    Ok(sovereignty::inspect(&request.document))
}

/// Remove exactly the chosen mark classes from one's own document. Wraps
/// `sovereignty::clean`; removal is each carrier's own strip, never reimplemented.
///
/// An empty selection defaults to every removable class, matching the other
/// surfaces. An unknown class id is refused by name rather than silently
/// skipped. The report carries the honest residual note the core returns, so a
/// clean is never read as a guarantee of an unmarked document.
#[tauri::command]
fn document_clean(request: DocumentCleanRequest) -> Result<sovereignty::CleanReport, String> {
    if request.document.is_empty() {
        return Err("the document to clean is empty".to_string());
    }
    let classes: Vec<MarkClass> = if request.classes.is_empty() {
        MarkClass::ALL.to_vec()
    } else {
        let mut resolved = Vec::with_capacity(request.classes.len());
        for id in &request.classes {
            match MarkClass::from_id(id) {
                Some(class) => resolved.push(class),
                None => return Err(format!("unknown mark class: {id}")),
            }
        }
        resolved
    };
    Ok(sovereignty::clean(&request.document, &classes))
}

/// Return one's own document to a pristine state: remove every mark class AND
/// every remaining invisible or format-control character, so the text
/// re-analyses fully clean. A DECLARED opt-in that also removes meaning-bearing
/// invisibles; the returned report NAMES that trade-off and REPORTS what it
/// removed, never silent. Wraps `sovereignty::pristine_clean`.
#[tauri::command]
fn document_pristine(request: DocumentPristineRequest) -> Result<sovereignty::PristineReport, String> {
    if request.document.is_empty() {
        return Err("the document to clean is empty".to_string());
    }
    Ok(sovereignty::pristine_clean(&request.document))
}

/// Read and report a file's C2PA content credential. Wraps
/// `c2pa_read::inspect_c2pa`.
///
/// A file with no credential is reported absent, not an error. The verdict is
/// exactly what the conformant reader returned, trust never overstated.
#[tauri::command]
fn c2pa_inspect(request: C2paInspectRequest) -> Result<c2pa_read::C2paReport, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to read".to_string());
    }
    c2pa_read::inspect_c2pa(&request.bytes, request.format_hint.as_deref())
        .map_err(|e| e.to_string())
}

// ─── Wordmark (word-choice / statistical marks) ─────────────────
//
// The AI-regulation tab's word-choice modules. These wrap `stegano_wm`'s
// pure-Rust layer: analysis under the honest verdict taxonomy, and a best-effort
// local scrub. They own no detection or editing logic of their own. The
// response carries data only; the informational copy is rendered from the
// locale catalogue by the frontend, never returned as a literal here.

#[derive(Debug, Deserialize)]
struct WordmarkAnalyzeRequest {
    text: String,
    #[serde(default)]
    acrostic_target: Option<String>,
    #[serde(default)]
    mark_key_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WordmarkScrubRequest {
    text: String,
    #[serde(default)]
    aggression: Option<String>,
}

#[derive(Debug, Serialize)]
struct WordmarkScrubResponse {
    text: String,
    synonym_positions: usize,
    positions_changed: usize,
}

/// Decode exactly 32 bytes from 64 hex characters, or `None`.
fn decode_wordmark_key(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Analyze a text for word-choice marks and return the verdict-taxonomy report.
/// Wraps `stegano_wm::analyze`; every report names the structural wall.
#[tauri::command]
fn wordmark_analyze(
    request: WordmarkAnalyzeRequest,
) -> Result<stegano_wm::WordmarkReport, String> {
    if request.text.is_empty() {
        return Err("the text to analyze is empty".to_string());
    }
    let mut opts = stegano_wm::AnalyzeOptions::default();
    if let Some(target) = request.acrostic_target.as_deref() {
        if !target.is_empty() {
            opts.acrostic_target = Some(target.to_string());
        }
    }
    if let Some(hex) = request.mark_key_hex.as_deref() {
        if !hex.is_empty() {
            match decode_wordmark_key(hex) {
                Some(key) => opts.our_key = Some(key),
                None => return Err("the key must be 64 hex characters (32 bytes)".to_string()),
            }
        }
    }
    Ok(stegano_wm::analyze(&request.text, &opts))
}

/// Perturb a word-choice channel locally, best-effort. Wraps
/// `stegano_wm::scrub_synonyms`; it is a disruption, never a claimed removal.
#[tauri::command]
fn wordmark_scrub(request: WordmarkScrubRequest) -> Result<WordmarkScrubResponse, String> {
    if request.text.is_empty() {
        return Err("the text to scrub is empty".to_string());
    }
    let aggression = match request.aggression.as_deref().unwrap_or("medium") {
        "light" => stegano_wm::Aggression::Light,
        "medium" => stegano_wm::Aggression::Medium,
        "heavy" => stegano_wm::Aggression::Heavy,
        other => {
            return Err(format!(
                "aggression must be light, medium, or heavy, not '{other}'"
            ))
        }
    };
    let report = stegano_wm::scrub_synonyms(&request.text, aggression);
    Ok(WordmarkScrubResponse {
        text: report.text,
        synonym_positions: report.positions_total,
        positions_changed: report.positions_changed,
    })
}

/// The instruction sent to the rewrite model. Not user-visible (it is a prompt
/// to the model), so it is an English literal like the other backend prompts.
const REWRITE_SYSTEM_PROMPT: &str = "Rewrite the text the user sends using \
substantially different wording, while preserving its exact meaning, facts, \
numbers and names. Vary sentence structure and word choice. Do not add or remove \
claims. Output only the rewritten text, nothing else.";

#[derive(Debug, Deserialize)]
struct WordmarkRewriteRequest {
    text: String,
    /// The server origin, e.g. http://localhost:11434 (local) or an online URL.
    base_url: String,
    model: String,
    /// The caller asserts the disclaimer was shown. Required for an online host.
    #[serde(default)]
    disclaimer_acknowledged: bool,
}

#[derive(Debug, Serialize)]
struct WordmarkRewriteResponse {
    text: String,
    /// "backend" when the model rewrote it, "floor" when the pure-Rust fallback
    /// ran because the backend was unreachable or its output was rejected.
    source: String,
    /// "local" or "online", the locality of the chosen backend.
    locality: String,
    /// True when the local re-clean parade ran over a backend rewrite.
    reclean_applied: bool,
}

/// Rewrite a text with a configured model, best-effort, to reduce a word-choice
/// mark. Orchestrates `stegano_wm::HttpBackend` through `scrub_via_backend`: the
/// disclaimer gate refuses an online host until the caller asserts the
/// disclaimer was shown (surfaced as the error code `disclaimer_required` so the
/// frontend can show it and retry), a local server (Ollama, LM Studio) needs no
/// disclaimer, the model's output is validated and a rejected or unreachable
/// backend falls back to the pure-Rust floor, and a backend rewrite is re-cleaned
/// locally of any freshly introduced character marks (the parade).
#[tauri::command]
fn wordmark_rewrite(request: WordmarkRewriteRequest) -> Result<WordmarkRewriteResponse, String> {
    if request.text.is_empty() {
        return Err("the text to rewrite is empty".to_string());
    }
    if request.base_url.trim().is_empty() {
        return Err("a model server URL is required".to_string());
    }
    let backend =
        stegano_wm::HttpBackend::new(&request.base_url, &request.model, REWRITE_SYSTEM_PROMPT);
    let reclean = |text: &str| sovereignty::clean(text, &MarkClass::ALL).cleaned_text;
    let report = stegano_wm::scrub_via_backend(
        &request.text,
        &backend,
        reclean,
        stegano_wm::Aggression::Medium,
        request.disclaimer_acknowledged,
    )
    .map_err(|e| match e {
        stegano_wm::GateError::DisclaimerRequired => "disclaimer_required".to_string(),
    })?;

    let source = match report.source {
        stegano_wm::ScrubSource::Backend => "backend",
        stegano_wm::ScrubSource::Floor => "floor",
    };
    let locality = match report.locality {
        stegano_wm::Locality::Local => "local",
        stegano_wm::Locality::Online => "online",
    };
    Ok(WordmarkRewriteResponse {
        text: report.text,
        source: source.to_string(),
        locality: locality.to_string(),
        reclean_applied: report.reclean_applied,
    })
}

// ─── Binoculars (AI-origin, embedded model only) ────────────────
//
// Two-model perplexity-ratio detection (SEC-WM3 brick 2). It needs per-token
// log-probabilities, which only the embedded llama.cpp backend provides, so
// these commands are real only in a build with the `embedded-llama` feature;
// without it they report unavailable by name. The two loaded models are held in
// a process-wide slot, guarded by a mutex so inference is serialized.

// The request fields are read only by the feature-gated commands below; without
// the embedded model they are deserialized but not read, so the dead-code lint
// is allowed just in that build, kept strict in the feature build.
#[cfg_attr(not(feature = "embedded-llama"), allow(dead_code))]
#[derive(Debug, Deserialize)]
struct BinocularsLoadRequest {
    observer_path: String,
    performer_path: String,
}

#[cfg_attr(not(feature = "embedded-llama"), allow(dead_code))]
#[derive(Debug, Deserialize)]
struct BinocularsAnalyzeRequest {
    text: String,
}

#[derive(Debug, Serialize)]
struct BinocularsResponse {
    score: f64,
}

/// Whether this build carries the embedded model, so the frontend can enable or
/// disable the Binoculars module up front. Always present, in every build.
#[tauri::command]
fn wordmark_binoculars_available() -> bool {
    cfg!(feature = "embedded-llama")
}

#[cfg(feature = "embedded-llama")]
struct LoadedModels(stegano_wm::EmbeddedLlamaBackend, stegano_wm::EmbeddedLlamaBackend);

// SAFETY: the models hold llama.cpp handles that are read-only for inference;
// every access goes through the mutex below, so use is serialized. This mirrors
// how the embedded backend guards its own process-wide state.
#[cfg(feature = "embedded-llama")]
unsafe impl Send for LoadedModels {}

#[cfg(feature = "embedded-llama")]
static BINOCULARS_MODELS: std::sync::Mutex<Option<LoadedModels>> = std::sync::Mutex::new(None);

/// Load the two GGUF models Binoculars scores with. Blocking, but Tauri runs
/// commands off the UI thread, so the interface stays responsive.
#[cfg(feature = "embedded-llama")]
#[tauri::command]
fn wordmark_binoculars_load(request: BinocularsLoadRequest) -> Result<(), String> {
    let observer = stegano_wm::EmbeddedLlamaBackend::load(&request.observer_path, "score")
        .map_err(|e| e.to_string())?;
    let performer = stegano_wm::EmbeddedLlamaBackend::load(&request.performer_path, "score")
        .map_err(|e| e.to_string())?;
    let mut slot = BINOCULARS_MODELS
        .lock()
        .map_err(|_| "the model slot is poisoned".to_string())?;
    *slot = Some(LoadedModels(observer, performer));
    Ok(())
}

#[cfg(not(feature = "embedded-llama"))]
#[tauri::command]
fn wordmark_binoculars_load(_request: BinocularsLoadRequest) -> Result<(), String> {
    Err("the embedded model is not available in this build".to_string())
}

/// Score a text with the two loaded models. Returns the Binoculars-family ratio;
/// the verdict is PROBABLE, never proof, and the frontend labels it so.
#[cfg(feature = "embedded-llama")]
#[tauri::command]
fn wordmark_binoculars_analyze(
    request: BinocularsAnalyzeRequest,
) -> Result<BinocularsResponse, String> {
    if request.text.is_empty() {
        return Err("the text to analyze is empty".to_string());
    }
    let slot = BINOCULARS_MODELS
        .lock()
        .map_err(|_| "the model slot is poisoned".to_string())?;
    let models = slot.as_ref().ok_or("load the two models first")?;
    let score = stegano_wm::binoculars(&models.0, &models.1, &request.text)
        .map_err(|e| e.to_string())?;
    Ok(BinocularsResponse { score })
}

#[cfg(not(feature = "embedded-llama"))]
#[tauri::command]
fn wordmark_binoculars_analyze(
    _request: BinocularsAnalyzeRequest,
) -> Result<BinocularsResponse, String> {
    Err("the embedded model is not available in this build".to_string())
}

// ─── Files ──────────────────────────────────────────────────────
//
// The Files tab runs the file layer's SAFE transform on a real document the
// operator picked: inspect (read-only, every readable format) and clean
// (removal, written back in the document's own format). These commands wrap
// `stegano_files`; they own no extraction, detection, removal or write-back
// logic of their own. Bytes travel as `Vec<u8>` the way the C2PA reader already
// does. A refusal, whether an unsupported format or a (format, class)
// combination whose lossless write-back the core cannot prove, surfaces the
// transform's own NAMED message, never a silent partial (invariant 2).

#[derive(Debug, Deserialize)]
struct FileInspectRequest {
    /// The document's raw bytes, read by the interface from the picked file.
    bytes: Vec<u8>,
    /// The document format, given as its file extension (for example `docx`,
    /// `odt`, `html`, `md`, `txt`). An unknown extension is refused by name.
    format: String,
}

#[derive(Debug, Deserialize)]
struct FileCleanRequest {
    bytes: Vec<u8>,
    format: String,
    /// Class ids to remove. Empty means every removable class, matching the
    /// text surfaces' default. An unknown id is refused by name.
    classes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FileCleanResponse {
    /// The written-back document bytes, in the same format as the input. The
    /// interface hands these back to the operator to save.
    bytes: Vec<u8>,
    /// The document's text after the clean, present ONLY for the text-native
    /// formats (Markdown, plain text) where the extracted text is the document
    /// itself. Absent for a container (DOCX, ODT), where the re-extracted text
    /// is a rendering, not the file, so surfacing it would misrepresent what was
    /// cleaned (invariant 2). The interface shows a text preview only when this
    /// is present.
    cleaned_text: Option<String>,
    /// Per requested class: how many marks were removed, measured by the core.
    removed: Vec<sovereignty::ClassRemoval>,
    /// True when the write-back changed the document bytes.
    altered: bool,
    /// The honest limits of a native clean, surfaced from the core unchanged.
    residual: Vec<String>,
    /// The source format's stable identifier, echoed back so the interface can
    /// pair the result with the document it cleaned.
    format: String,
}

/// Resolve a format string (a file extension) into a [`FileFormat`]. An empty or
/// unknown extension is refused by name rather than guessed (invariant 2).
fn file_format_from_string(format: &str) -> Result<FileFormat, String> {
    let trimmed = format.trim();
    if trimmed.is_empty() {
        return Err("no file format was given: the picked file has no extension".to_string());
    }
    FileFormat::from_extension(trimmed).map_err(|e| e.to_string())
}

/// Inspect a picked document and report every mark this tool can see. Wraps
/// `stegano_files::inspect_file`; it reimplements no extraction or detection.
///
/// Read-only, supported for every readable format. An empty file or an unknown
/// format is refused by name.
#[tauri::command]
fn file_inspect(request: FileInspectRequest) -> Result<sovereignty::InspectionReport, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to inspect".to_string());
    }
    let format = file_format_from_string(&request.format)?;
    inspect_file(&request.bytes, format).map_err(|e| e.to_string())
}

/// Clean the chosen mark classes from a picked document and hand back the
/// written-back bytes, in the same format as the input. Wraps
/// `stegano_files::clean_file`; removal and write-back are the file layer's own.
///
/// An empty selection defaults to every removable class, matching the text
/// surfaces. An unknown class id is refused by name. A (format, class)
/// combination whose lossless write-back the core cannot prove (a container
/// homoglyph clean, an HTML clean, a lossy re-encoding) surfaces the transform's
/// own named message rather than a silent partial (invariant 2). The response
/// carries the honest residual note the core returns, so a clean is never read
/// as a guarantee of an unmarked document.
#[tauri::command]
fn file_clean(request: FileCleanRequest) -> Result<FileCleanResponse, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to clean".to_string());
    }
    let format = file_format_from_string(&request.format)?;
    let classes: Vec<MarkClass> = if request.classes.is_empty() {
        MarkClass::ALL.to_vec()
    } else {
        let mut resolved = Vec::with_capacity(request.classes.len());
        for id in &request.classes {
            match MarkClass::from_id(id) {
                Some(class) => resolved.push(class),
                None => return Err(format!("unknown mark class: {id}")),
            }
        }
        resolved
    };

    let outcome = clean_file(&request.bytes, format, &classes).map_err(|e| e.to_string())?;

    // The cleaned text is the document only for the text-native formats. For a
    // container the re-extracted text is a rendering, not the file, so it is not
    // surfaced as a preview of what was cleaned.
    let text_native = matches!(
        outcome.format,
        FileFormat::Markdown | FileFormat::PlainText
    );
    Ok(FileCleanResponse {
        cleaned_text: if text_native {
            Some(outcome.cleaned_text)
        } else {
            None
        },
        removed: outcome.removed,
        altered: outcome.altered,
        residual: outcome.residual,
        format: outcome.format.name().to_string(),
        bytes: outcome.bytes,
    })
}

#[derive(Debug, Deserialize)]
struct FileStripRequest {
    /// The file's raw bytes, read by the interface from the picked file.
    bytes: Vec<u8>,
    /// The file format, given as its file extension. A format with no strippable
    /// metadata surface is refused by name.
    format: String,
}

#[derive(Debug, Serialize)]
struct FileStripResponse {
    /// True when the strip changed the file bytes (metadata was present).
    altered: bool,
    /// True by construction: a strip removes only metadata surfaces and our
    /// channel, never the readable content.
    content_identical: bool,
    /// The source format's stable identifier, echoed back.
    format: String,
    /// The stripped file bytes, in the same format, for the interface to save.
    bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct FilePristineRequest {
    /// The text file's raw bytes, read by the interface from the picked file.
    bytes: Vec<u8>,
    /// The document format, given as its file extension. A container or markup
    /// format is refused by name.
    format: String,
}

#[derive(Debug, Serialize)]
struct FilePristineResponse {
    /// The document text after the pristine clean, present for the text-native
    /// formats where the extracted text is the document.
    cleaned_text: Option<String>,
    /// Per mark class: what the conservative clean removed first.
    class_removed: Vec<sovereignty::ClassRemoval>,
    /// Invisible or format-control characters removed beyond the mark classes.
    invisibles_removed: usize,
    /// The honest caveat and what was removed, surfaced from the core unchanged.
    notes: Vec<String>,
    /// True when the pristine clean changed the file bytes.
    altered: bool,
    /// The source format's stable identifier, echoed back.
    format: String,
    /// The cleaned file bytes, in the same format, for the interface to save.
    bytes: Vec<u8>,
}

/// Strip a picked file's metadata (native and our own channel) and hand back the
/// stripped bytes, with the readable content byte-identical. Wraps
/// `stegano_files::strip_file`.
///
/// A format with no strippable metadata surface is refused by name rather than
/// returned unchanged (invariant 2).
#[tauri::command]
fn file_strip(request: FileStripRequest) -> Result<FileStripResponse, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to strip".to_string());
    }
    let format = file_format_from_string(&request.format)?;
    let outcome = strip_file(&request.bytes, format).map_err(|e| e.to_string())?;
    Ok(FileStripResponse {
        altered: outcome.altered,
        content_identical: outcome.content_identical,
        format: outcome.format.name().to_string(),
        bytes: outcome.bytes,
    })
}

/// Pristine-clean a picked text file (remove every mark class AND every remaining
/// invisible) and hand back the cleaned bytes. A DECLARED opt-in that names its
/// meaning-bearing trade-off. Wraps `stegano_files::pristine_file`.
///
/// A container or markup format is refused by name, pointing to a strip plus a
/// full clean as the best-effort pair (invariant 2).
#[tauri::command]
fn file_pristine(request: FilePristineRequest) -> Result<FilePristineResponse, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to clean".to_string());
    }
    let format = file_format_from_string(&request.format)?;
    let outcome = pristine_file(&request.bytes, format).map_err(|e| e.to_string())?;
    let text_native = matches!(outcome.format, FileFormat::Markdown | FileFormat::PlainText);
    Ok(FilePristineResponse {
        cleaned_text: if text_native {
            Some(outcome.cleaned_text)
        } else {
            None
        },
        class_removed: outcome.class_removed,
        invisibles_removed: outcome.invisibles_removed,
        notes: outcome.notes,
        altered: outcome.altered,
        format: outcome.format.name().to_string(),
        bytes: outcome.bytes,
    })
}

#[derive(Debug, Deserialize)]
struct FileAnalyzeRequest {
    /// The document's raw bytes, read by the interface from the picked file.
    bytes: Vec<u8>,
    /// The document format, given as its file extension. An unknown extension, or
    /// a format whose text this layer cannot read, is refused by name.
    format: String,
}

/// Analyse a picked document: read its visible text with the file layer, then run
/// the SAME forensic analysis the text `forensic_analyze` command runs, and return
/// the identical report shape so the interface renders a file's analysis exactly
/// as it renders a pasted text's. Wraps `stegano_files::extract_text` then
/// `stegano_core::forensic::analyze`; it owns no extraction or analysis of its own.
///
/// An empty file, an unknown format, or a document whose text cannot be read is
/// refused by the file layer's own NAMED error rather than analysed as an empty
/// report (invariant 2: no silent degradation).
#[tauri::command]
fn file_analyze(request: FileAnalyzeRequest) -> Result<forensic::ForensicReport, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to analyze".to_string());
    }
    let format = file_format_from_string(&request.format)?;
    let extracted = extract_text(&request.bytes, format).map_err(|e| e.to_string())?;
    Ok(forensic::analyze(&extracted.text))
}

#[derive(Debug, Deserialize)]
struct FileConcealRequest {
    /// The cover document's raw bytes, read by the interface from the picked file.
    bytes: Vec<u8>,
    /// The document format, given as its file extension. An unknown extension, or
    /// a format whose in-place conceal is not solved (a container, HTML, or a
    /// lowered foreign source), is refused by name.
    format: String,
    /// The secret to hide inside the cover document.
    secret: String,
    /// The carriers to place the secret with, resolved exactly as `compose` does.
    carriers: Vec<String>,
    /// The confidentiality layer id, or `None`/`"none"` to travel in the clear.
    #[serde(default)]
    cipher: Option<String>,
    /// The passphrase the cipher derives its key from. Empty with a cipher
    /// selected is refused by name, never silently downgraded to no encryption.
    #[serde(default)]
    password: Option<String>,
    /// Saturation mode: fill each carrier's channel in the file with the secret
    /// repeated, the aggressive variant that survives a heavy cut (SATURATE).
    #[serde(default)]
    saturate: bool,
}

#[derive(Debug, Serialize)]
struct FileConcealResponse {
    /// The marked document bytes, in the SAME format as the input. These are the
    /// file layer's real compose output, re-encoded in the document's own
    /// encoding; nothing is predicted or truncated (invariant 2). The interface
    /// hands these back to the operator to save.
    bytes: Vec<u8>,
    /// The document's text after the conceal, present ONLY for the text-native
    /// formats (Markdown, plain text) where the extracted text is the document
    /// itself. Concealing succeeds only for those formats in this build, so this
    /// is present on every success; it is still gated on the format so a future
    /// container path never surfaces a rendering as the file (invariant 2).
    marked_text: Option<String>,
    /// Carriers the core actually applied, in application order, from the core's
    /// own `methods_used`, never a predicted list.
    carriers: Vec<String>,
    /// The confidentiality layer applied, or `None` when the secret travelled in
    /// the clear. Named from the selection that was actually used.
    cipher: Option<String>,
    /// The source format's stable identifier, echoed back so the interface can
    /// pair the result with the document it marked.
    format: String,
    /// Bytes of the source document, measured from the input.
    source_len: usize,
    /// Bytes of the marked document, measured from the output.
    marked_len: usize,
    /// Bytes of the secret concealed, measured from the input.
    secret_len: usize,
}

/// Conceal a secret INSIDE a picked document and hand back the marked document
/// bytes, in the SAME format as the input. Wraps `stegano_files::conceal_file`;
/// it owns no placement, carrier, cipher or write-back logic of its own.
///
/// This is the zero-loss, in-place path, never a conversion: the file layer
/// places the secret through the frozen core under the concealment mission and
/// writes the marked document back in its own encoding. The carrier and cipher
/// selection are resolved exactly as the text `compose` command resolves them, so
/// the selection UI is unchanged.
///
/// A container (DOCX, ODT) or HTML cover, a format whose extraction lowers a
/// foreign source, an empty secret, a capacity shortfall under the concealment
/// ceiling, and a cipher chosen with an empty passphrase each surface the
/// engine's own NAMED refusal rather than a silent or partial result (invariant
/// 2). The empty-passphrase case is named here by `crypto_selection`, matching
/// the file layer's own `MissingPassphrase`.
#[tauri::command]
fn file_conceal(request: FileConcealRequest) -> Result<FileConcealResponse, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to conceal into".to_string());
    }
    let format = file_format_from_string(&request.format)?;

    // Resolve the carrier selection exactly as `compose` does: normalise the
    // order, then box each carrier through the shared registry.
    let ordered = registry::normalise_carrier_selection(&request.carriers)?;
    let boxed: Vec<Box<dyn StegoMethod>> = ordered
        .iter()
        .map(|id| registry::carrier(id))
        .collect::<Result<_, _>>()?;
    let refs: Vec<&dyn StegoMethod> = boxed.iter().map(|b| b.as_ref()).collect();

    // Resolve the cipher selection exactly as `compose` does. An empty passphrase
    // with a cipher selected is refused BY NAME here, never silently downgraded.
    let selection = crypto_selection(request.cipher.as_deref(), request.password.as_deref())?;
    let crypto_pair = selection
        .as_ref()
        .map(|(method, pass)| (method.as_ref(), pass.as_str()));

    let outcome =
        conceal_file(&request.bytes, format, &request.secret, &refs, crypto_pair, request.saturate)
            .map_err(|e| e.to_string())?;

    // The marked text is the document only for the text-native formats. For a
    // container it would be a rendering, not the file, so it is not surfaced.
    let text_native = matches!(outcome.format, FileFormat::Markdown | FileFormat::PlainText);
    Ok(FileConcealResponse {
        marked_text: if text_native {
            Some(outcome.marked_text)
        } else {
            None
        },
        carriers: outcome.carriers,
        cipher: outcome.cipher,
        format: outcome.format.name().to_string(),
        source_len: outcome.source_len,
        marked_len: outcome.marked_len,
        secret_len: outcome.secret_len,
        bytes: outcome.bytes,
    })
}

#[derive(Debug, Deserialize)]
struct FileDecodeRequest {
    /// The received document's raw bytes, read by the interface from the picked
    /// file.
    bytes: Vec<u8>,
    /// The document format, given as its file extension. An unknown extension, or a
    /// format whose text this layer cannot read, is refused by name.
    format: String,
    /// The passphrase the layer was encrypted under, when one was. Absent or empty
    /// means the layer was not encrypted; a wrong or missing passphrase surfaces the
    /// cascade's own named failure through `reveal`, never a silent empty.
    #[serde(default)]
    password: Option<String>,
    /// The carrier to read the layer through, or `None`/empty to try every carrier,
    /// resolved exactly as the text `reveal` command resolves it.
    #[serde(default)]
    carrier: Option<String>,
}

/// Recover a hidden layer from a picked document: read its visible text with the
/// file layer, then run the SAME core reveal path the text `reveal` command runs,
/// and return the identical [`RevealResponse`] so the interface renders a file's
/// decode exactly as it renders a pasted text's (recovered layer, carrier, cipher,
/// integrity). Wraps `stegano_files::extract_text` then the existing `reveal`
/// command; it owns no extraction or decode logic of its own.
///
/// An empty file, an unknown format, or a document whose text cannot be read is
/// refused by the file layer's own NAMED error. A readable document that carries no
/// recoverable layer surfaces the decode cascade's own NAMED failure through
/// `reveal` (`NothingDetected`), never a silent empty report (invariant 2: no
/// silent degradation). When the recovered layer itself carries an attached file,
/// that file is read back through the existing `recover_attachments` path; this
/// command changes nothing about that, it only reaches the layer from a file.
#[tauri::command]
fn file_decode(request: FileDecodeRequest) -> Result<RevealResponse, String> {
    if request.bytes.is_empty() {
        return Err("no file bytes were provided to decode".to_string());
    }
    let format = file_format_from_string(&request.format)?;
    let extracted = extract_text(&request.bytes, format).map_err(|e| e.to_string())?;
    // Reuse the text decode path exactly: same carrier resolution, same cipher
    // set, same pipeline cascade. This command adds only the file extraction, so a
    // file decodes through the very logic a pasted text decodes through.
    reveal(extracted.text, request.carrier, request.password)
}

// ─── Payload shaping ────────────────────────────────────────────
//
// Two frozen-core utilities the desktop app could not reach before: attaching a
// small file to the layer to hide, and making a payload smaller before it is
// hidden. These commands own no packing or compression logic of their own. They
// wrap `stegano_core::utils::FileEmbed` and `stegano_core::utils::Compression`,
// carry bytes as `Vec<u8>` the way the C2PA reader already does, and report
// every size measured, never asserted. A refusal (an empty file, a file the
// engine judges too large, an input this surface did not produce) surfaces the
// core's own named error, never a silent empty result (invariant 2).

#[derive(Debug, Serialize)]
struct AttachPayloadResponse {
    /// The text with the file attached, ready to be the layer Compose hides.
    text: String,
    filename: String,
    /// Bytes of file placed into the text, measured.
    attached_bytes: usize,
    chars_before: usize,
    chars_after: usize,
}

#[derive(Debug, Serialize)]
struct RecoveredFile {
    filename: String,
    byte_count: usize,
    /// The recovered file contents, as bytes. When the file was made smaller
    /// before hiding, these are the smaller bytes; `expand_payload` restores them.
    data: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct RecoverAttachmentsResponse {
    present: bool,
    count: usize,
    files: Vec<RecoveredFile>,
}

#[derive(Debug, Serialize)]
struct CompressPayloadResponse {
    /// The smaller payload, as bytes.
    compressed: Vec<u8>,
    original_bytes: usize,
    compressed_bytes: usize,
    /// compressed_bytes / original_bytes, measured. At or above 1.0 the payload
    /// did not get smaller, which the interface shows as it is.
    ratio: f64,
}

#[derive(Debug, Serialize)]
struct ExpandPayloadResponse {
    /// The restored payload as text, when it is valid UTF-8; absent otherwise.
    plaintext: Option<String>,
    byte_count: usize,
    compressed_bytes: usize,
}

/// Attach a small file to a text, so it can be hidden as the layer. Wraps
/// `FileEmbed::embed`; it owns no packing logic. An empty file, or a name that
/// would break the container, is refused by name here; a file the engine judges
/// too large surfaces the core's own named refusal rather than a truncation.
#[tauri::command]
fn attach_payload(
    text: String,
    filename: String,
    data: Vec<u8>,
) -> Result<AttachPayloadResponse, String> {
    if filename.trim().is_empty() {
        return Err("the payload file needs a name".to_string());
    }
    if filename.contains('|') {
        return Err("the payload file name must not contain the character |".to_string());
    }
    if data.is_empty() {
        return Err("the payload file is empty".to_string());
    }
    let combined = FileEmbed::new()
        .embed(&text, &filename, &data)
        .map_err(|e| e.to_string())?;
    Ok(AttachPayloadResponse {
        chars_before: text.chars().count(),
        chars_after: combined.chars().count(),
        attached_bytes: data.len(),
        text: combined,
        filename,
    })
}

/// List the files attached to a text and return their contents. Wraps
/// `FileEmbed::extract`/`detect`; it reports what is there, never a guess. An
/// empty input is a named refusal.
#[tauri::command]
fn recover_attachments(text: String) -> Result<RecoverAttachmentsResponse, String> {
    if text.is_empty() {
        return Err("the text to recover from is empty".to_string());
    }
    let embedder = FileEmbed::new();
    let files: Vec<RecoveredFile> = embedder
        .extract(&text)
        .into_iter()
        .map(|file| RecoveredFile {
            filename: file.name,
            byte_count: file.data.len(),
            data: file.data,
        })
        .collect();
    Ok(RecoverAttachmentsResponse {
        present: embedder.detect(&text),
        count: files.len(),
        files,
    })
}

/// Make a payload smaller before it is hidden, and report both sizes measured.
/// Wraps `Compression::compress`; it owns no compression logic. An empty payload
/// or an out-of-range effort is refused by name.
#[tauri::command]
fn compress_payload(data: Vec<u8>, level: Option<u32>) -> Result<CompressPayloadResponse, String> {
    if data.is_empty() {
        return Err("the payload to make smaller is empty".to_string());
    }
    let level = level.unwrap_or(9);
    if level > 9 {
        return Err("the effort must be between 0 and 9".to_string());
    }
    let compressed = Compression::new()
        .compress(&data, level)
        .map_err(|e| e.to_string())?;
    let ratio = compressed.len() as f64 / data.len() as f64;
    Ok(CompressPayloadResponse {
        original_bytes: data.len(),
        compressed_bytes: compressed.len(),
        ratio,
        compressed,
    })
}

/// Restore a payload that was made smaller. Wraps `Compression::decompress`;
/// input that this surface did not produce is refused by name, never returned
/// unchanged.
#[tauri::command]
fn expand_payload(compressed: Vec<u8>) -> Result<ExpandPayloadResponse, String> {
    if compressed.is_empty() {
        return Err("the payload to restore is empty".to_string());
    }
    let expanded = Compression::new()
        .decompress(&compressed)
        .map_err(|e| e.to_string())?;
    let byte_count = expanded.len();
    Ok(ExpandPayloadResponse {
        plaintext: String::from_utf8(expanded).ok(),
        byte_count,
        compressed_bytes: compressed.len(),
    })
}

// ─── Runtime configuration ──────────────────────────────────────
//
// The runtime configuration (the per-mission planning densities and the
// key-derivation parameters) is owned by `stegano_mcp::settings::Settings`,
// the same type the MCP channel and the REST server expose as
// `settings_read` / `settings_update`. These two commands dispatch through
// `stegano_mcp::tools::call`, the exact function both of those surfaces call,
// so the desktop app validates a change identically: an out-of-range or
// malformed value is refused by name by the core's own validated setter, never
// clamped or ignored here.
//
// Scope: the desktop store is held in memory for the running process. A change
// takes effect immediately and is read back from the store, so the interface
// reports the value the core actually stored, never an optimistic echo. It is
// not written to disk: at the next start the engine returns to its defaults.
// The interface copy says so; it never implies a persistence that does not
// exist (invariant 2).

/// The process-wide configuration store the desktop app edits. In memory only,
/// mirroring the in-memory store the other surfaces use in their own tests; the
/// validated setter and the field set are the shared ones from `stegano_mcp`.
fn settings_store() -> &'static Mutex<SettingsStore> {
    static STORE: OnceLock<Mutex<SettingsStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(SettingsStore::in_memory(Settings::default())))
}

/// Map a command outcome onto a Tauri result. A refusal becomes an `Err`
/// carrying the core's own named reason, so the interface can show which field
/// was refused and why, verbatim, rather than a generic message.
fn outcome_to_result(outcome: Outcome) -> Result<serde_json::Value, String> {
    match outcome {
        Outcome::Done(value) => Ok(value),
        Outcome::Refused { reason, .. } => Err(reason),
        Outcome::BadArguments(reason) => Err(reason),
        Outcome::Unknown(reason) => Err(reason),
    }
}

/// Read the configuration in force through the shared dispatcher. Returns the
/// editable view and the accepted range of every field. The bearer token is
/// never part of the view.
fn read_settings(store: &mut SettingsStore) -> Result<serde_json::Value, String> {
    outcome_to_result(mcp_tools::call("settings_read", &serde_json::json!({}), store))
}

/// Apply a partial update through the shared dispatcher. Nothing changes unless
/// every field is accepted; on success the stored settings are read back into
/// the result so the caller sees what the core actually stored.
fn apply_settings(
    store: &mut SettingsStore,
    update: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let arguments = serde_json::json!({ "settings": update });
    outcome_to_result(mcp_tools::call("settings_update", &arguments, store))
}

/// Read the runtime configuration and the accepted range of every field.
#[tauri::command]
fn settings_read() -> Result<serde_json::Value, String> {
    let mut store = settings_store()
        .lock()
        .map_err(|_| "the settings store is unavailable".to_string())?;
    read_settings(&mut store)
}

/// Apply a partial change to the runtime configuration, validated by the core.
/// A rejected value leaves the stored configuration untouched and returns the
/// core's named refusal.
#[tauri::command]
fn settings_update(update: serde_json::Value) -> Result<serde_json::Value, String> {
    let mut store = settings_store()
        .lock()
        .map_err(|_| "the settings store is unavailable".to_string())?;
    apply_settings(&mut store, &update)
}

// ─── Main ───────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Point the locale loader at the bundled catalogues before any command
            // runs. Where the installer places them differs by platform (beside the
            // executable on Windows, inside the .app on macOS, under the AppImage
            // mount on Linux), so the resource directory Tauri resolves is the one
            // reliable anchor. The loader checks STEGANOHERO_LOCALES_DIR first, so
            // setting it here makes the installed app find its languages; the
            // compile-time path only ever served the dev tree.
            use tauri::Manager;
            if let Ok(resource_dir) = app.path().resource_dir() {
                // The catalogues may land in a locales/ subdirectory or flat in the
                // resource root, depending on the bundler; probe for the base
                // catalogue and point the override at wherever it actually is.
                for candidate in [resource_dir.join("locales"), resource_dir.clone()] {
                    if candidate.join("en.json").is_file() {
                        std::env::set_var("STEGANOHERO_LOCALES_DIR", &candidate);
                        break;
                    }
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            locale_environment,
            load_locale,
            list_carriers,
            list_ciphers,
            compose,
            compose_sealed,
            pqc_keypair,
            export_formats,
            export_result,
            document_text,
            mcp_setup_info,
            mcp_configure,
            carrier_capacity,
            validate_carriers,
            measure_payload,
            mission_capacity,
            recommend_settings,
            reveal,
            reveal_sealed,
            reveal_traced,
            forensic_analyze,
            detect,
            compute_metrics,
            strip_carriers,
            generate_signing_identity,
            provenance_mark,
            provenance_verify,
            canary_generate,
            canary_trace,
            document_inspect,
            document_clean,
            document_pristine,
            wordmark_analyze,
            wordmark_scrub,
            wordmark_rewrite,
            wordmark_binoculars_available,
            wordmark_binoculars_load,
            wordmark_binoculars_analyze,
            c2pa_inspect,
            file_inspect,
            file_clean,
            file_strip,
            file_pristine,
            file_analyze,
            file_conceal,
            file_decode,
            attach_payload,
            recover_attachments,
            compress_payload,
            expand_payload,
            settings_read,
            settings_update,
        ])
        .run(tauri::generate_context!())
        .expect("error running SteganoHero");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cover long enough for every carrier's capacity rule at once: nine
    /// characters per payload byte for the two spacing carriers, and one
    /// substitutable visible position per bit for the substitution carrier.
    fn long_cover() -> String {
        PROBE_SENTENCE.repeat(30)
    }

    #[test]
    fn compose_returns_the_full_cover_text() {
        let cover = long_cover();
        let response = compose(
            cover.clone(),
            "meeting at nine".to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .expect("composition must succeed");

        assert!(response.cover_restored, "stripping must restore the cover");
        assert_eq!(response.cover_chars, cover.chars().count());
        assert!(response.result_chars > response.cover_chars);
        assert!(response.stego_text.contains("The archive was opened"));
    }

    #[test]
    fn compose_reports_the_analyser_verdict_on_the_produced_document() {
        // Compose is permissive: it places, it does not gate on the mission
        // ceiling. The honest overlay is the verdict the tool's own analyser
        // reaches on the exact document produced, carried back so the operator
        // sees what an analyst would (COMPOSE-4).
        let cover = long_cover();
        let response = compose(
            cover,
            "meeting at nine".to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .expect("composition must succeed");

        assert!(
            response.noise_density > 0.0,
            "a placed layer leaves a measurable channel density"
        );
        assert!(
            !response.verdict.trim().is_empty(),
            "the analyser verdict on the produced document travels with the result"
        );
        // The figure must be the one the core's own report returns on that text.
        let report = pipeline::overflow_report(&response.stego_text);
        assert_eq!(response.noise_density, report.noise_density);
        assert_eq!(response.verdict, report.verdict);
    }

    #[test]
    fn compose_saturate_fills_the_channel_and_reveals() {
        // SAT-E2E, GUI. The saturation toggle fills the channel far past a single
        // copy, the visible text is unchanged, and the secret still reveals.
        let cover = long_cover();
        let count =
            |s: &str| s.chars().filter(|c| matches!(*c, '\u{200B}' | '\u{200C}')).count();

        let normal = compose(
            cover.clone(),
            "saturated gui".to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .unwrap();
        let saturated = compose(
            cover,
            "saturated gui".to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            true,
        )
        .unwrap();

        assert!(
            count(&saturated.stego_text) > count(&normal.stego_text) * 2,
            "the saturated channel is far denser than a single copy"
        );
        assert!(saturated.cover_restored, "the visible text is unchanged under saturation");

        let revealed = reveal(saturated.stego_text, Some("zero_width".to_string()), None).unwrap();
        assert_eq!(revealed.hidden_text.as_deref(), Some("saturated gui"));
    }

    #[test]
    fn every_carrier_composes_and_strips_back_to_the_cover() {
        let cover = long_cover();
        for id in registry::CARRIER_ORDER {
            let composed = compose(
                cover.clone(),
                "one carrier at a time".to_string(),
                vec![id.to_string()],
                None,
                None,
                false,
                false,
            )
            .unwrap_or_else(|e| panic!("carrier {id} must compose: {e}"));

            assert!(
                composed.cover_restored,
                "carrier {id} must strip back to the cover text exactly"
            );
        }
    }

    #[test]
    fn compose_sealed_and_reveal_sealed_round_trip_for_a_recipient() {
        // The GUI recipient flow: generate a keypair, seal-and-hide in one call,
        // then reveal-and-open in one call, with no shared passphrase.
        let keypair = pqc_keypair();
        let cover = long_cover();
        let secret = "the courier arrives on the fourth";

        let composed = compose_sealed(
            cover.clone(),
            secret.to_string(),
            vec!["zero_width".to_string()],
            keypair.public_key.clone(),
            false,
            false,
        )
        .expect("sealing and hiding must succeed");
        assert!(composed.sealed_to_recipient, "the result reports it was sealed");
        assert!(composed.cover_restored, "stripping still restores the cover");
        assert!(!composed.stego_text.contains(secret), "the secret is not in the clear");

        let revealed = reveal_sealed(
            composed.stego_text,
            Some("zero_width".to_string()),
            keypair.secret_key.clone(),
        )
        .expect("revealing and opening must succeed");
        assert!(revealed.opened_for_recipient, "the result reports it was opened");
        assert_eq!(revealed.hidden_text.as_deref(), Some(secret), "the recipient recovers the secret");
    }

    #[test]
    fn reveal_sealed_with_the_wrong_key_is_refused_by_name() {
        let recipient = pqc_keypair();
        let intruder = pqc_keypair();
        let cover = long_cover();

        let composed = compose_sealed(
            cover,
            "for the recipient only".to_string(),
            vec!["zero_width".to_string()],
            recipient.public_key,
            false,
            false,
        )
        .unwrap();

        let outcome = reveal_sealed(
            composed.stego_text,
            Some("zero_width".to_string()),
            intruder.secret_key,
        );
        assert!(outcome.is_err(), "a wrong key must not open the payload");
    }

    #[test]
    fn compose_sealed_with_a_malformed_recipient_key_is_refused() {
        let cover = long_cover();
        let outcome = compose_sealed(
            cover,
            "x".to_string(),
            vec!["zero_width".to_string()],
            B64.encode(b"not a real ML-KEM public key"),
            false,
            false,
        );
        assert!(outcome.is_err(), "a malformed recipient key must be refused");
    }

    #[test]
    fn export_result_is_byte_faithful_for_text() {
        // A marked cover exported to txt on the desktop must come back exactly, so
        // its hidden layer survives the download.
        let marked = "the drop is at\u{200B} noon";
        let bytes = export_result(marked.to_string(), "txt".to_string()).expect("txt export");
        assert_eq!(String::from_utf8(bytes).unwrap(), marked, "txt export is byte-faithful");
    }

    #[test]
    fn export_result_renders_a_rich_target_non_empty() {
        let bytes = export_result("a finding".to_string(), "rtf".to_string()).expect("rtf export");
        assert!(!bytes.is_empty(), "the rtf export has bytes to save");
    }

    #[test]
    fn export_result_refuses_an_unknown_target() {
        assert!(export_result("x".to_string(), "xyz".to_string()).is_err(), "unknown target refused");
    }

    #[test]
    fn export_result_renders_a_native_pdf() {
        let bytes = export_result("a short report".to_string(), "pdf".to_string()).expect("pdf export");
        assert!(bytes.starts_with(b"%PDF"), "the desktop pdf export is a PDF document");
        assert!(export_formats().contains(&"pdf".to_string()), "pdf is offered in the picker");
    }

    #[test]
    fn document_text_extracts_a_files_text() {
        // A Markdown document resolves to its text, so any panel can accept a file.
        let bytes = b"# Note\n\nthe body of the note".to_vec();
        let text = document_text(bytes, "md".to_string()).expect("markdown extracts");
        assert!(text.contains("body of the note"), "the text was extracted");
    }

    #[test]
    fn document_text_refuses_empty_bytes_by_name() {
        assert!(document_text(Vec::new(), "md".to_string()).is_err(), "empty bytes refused");
    }

    #[test]
    fn export_formats_lists_the_shared_target_set() {
        let formats = export_formats();
        assert!(formats.contains(&"txt".to_string()), "txt offered");
        assert!(formats.contains(&"html".to_string()), "html offered");
        assert!(formats.contains(&"md".to_string()), "md offered");
    }

    /// The round-trip flag the interface displays must match what the engine
    /// actually does. This test holds both before and after the read path of a
    /// carrier is repaired, so it never needs editing: it only guarantees that
    /// the interface never advertises a carrier the engine cannot read back.
    #[test]
    fn the_round_trip_flag_matches_engine_behaviour() {
        let cover = long_cover();
        let secret = "flag consistency";
        for id in registry::CARRIER_ORDER {
            let actual = match compose(
                cover.clone(),
                secret.to_string(),
                vec![id.to_string()],
                None,
                None,
                false,
                false,
            ) {
                Ok(composed) => match reveal(composed.stego_text, Some(id.to_string()), None) {
                    Ok(revealed) => revealed.hidden_text.as_deref() == Some(secret),
                    Err(_) => false,
                },
                Err(_) => false,
            };
            assert_eq!(
                actual,
                carrier_round_trip(id),
                "carrier {id} is reported as round-tripping {}, engine says {actual}",
                carrier_round_trip(id)
            );
        }
    }

    #[test]
    fn a_verified_carrier_returns_the_layer_unchanged() {
        let cover = long_cover();
        let secret = "verified carriers only";
        let mut verified = 0;
        for id in registry::CARRIER_ORDER {
            if !carrier_round_trip(id) {
                continue;
            }
            verified += 1;
            let composed = compose(
                cover.clone(),
                secret.to_string(),
                vec![id.to_string()],
                None,
                None,
                false,
                false,
            )
            .unwrap_or_else(|e| panic!("carrier {id} must compose: {e}"));
            let revealed = reveal(composed.stego_text, Some(id.to_string()), None)
                .unwrap_or_else(|e| panic!("carrier {id} must reveal: {e}"));
            assert_eq!(revealed.hidden_text.as_deref(), Some(secret));
            assert!(revealed.integrity, "carrier {id} must report integrity");
        }
        assert!(verified > 0, "at least one carrier must round-trip");
    }

    // Un-ignored 2026-08-17 when F4 wired the format layer into the pipeline.
    // It was the written specification of F0 and F10 for two iterations, and it
    // passes with its assertions unweakened: per-carrier full copies, homoglyph
    // last, and cover_restored.
    #[test]
    fn all_four_carriers_combine_in_the_order_the_core_requires() {
        let cover = long_cover();
        let secret = "four carriers at once";
        let selection: Vec<String> = registry::CARRIER_ORDER
            .iter()
            .map(|s| s.to_string())
            .collect();

        let composed = compose(cover.clone(), secret.to_string(), selection, None, None, false, false)
            .expect("all four carriers must compose together");
        assert_eq!(composed.carriers_applied.len(), 4);
        assert_eq!(
            composed.carriers_applied.last().map(String::as_str),
            Some("homoglyph"),
            "the carrier that rewrites visible text must run last"
        );
        assert!(composed.cover_restored, "stripping all four must restore the cover");

        // Automatic carrier detection must find the layer.
        let revealed = reveal(composed.stego_text.clone(), None, None)
            .expect("the combined text must reveal");
        assert_eq!(revealed.hidden_text.as_deref(), Some(secret));

        // Every carrier whose read path works must hold a full copy of its own.
        for id in registry::CARRIER_ORDER {
            if !carrier_round_trip(id) {
                continue;
            }
            let single = reveal(composed.stego_text.clone(), Some(id.to_string()), None)
                .unwrap_or_else(|e| panic!("carrier {id} must carry its own copy: {e}"));
            assert_eq!(
                single.hidden_text.as_deref(),
                Some(secret),
                "carrier {id} must hold a full copy of the layer"
            );
        }
    }

    #[test]
    fn a_selection_in_any_order_is_normalised_before_the_core_sees_it() {
        // The operator ticked the substitution carrier first; the command must
        // still produce a legal composition rather than a core-level refusal.
        let composed = compose(
            long_cover(),
            "order does not matter to the operator".to_string(),
            vec!["homoglyph".to_string(), "zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .expect("a reversed selection must still compose");
        assert_eq!(composed.carriers_applied, vec!["zero_width", "homoglyph"]);
    }

    #[test]
    fn illegal_selections_are_reported_before_composing() {
        assert!(validate_carriers(vec!["not_a_carrier".to_string()]).is_err());
        let ordered = validate_carriers(vec!["homoglyph".to_string(), "bidi".to_string()])
            .expect("a legal selection must validate");
        assert_eq!(ordered, vec!["bidi", "homoglyph"]);
    }

    #[test]
    fn every_cipher_round_trips_through_a_carrier() {
        let cover = long_cover();
        let secret = "encrypted layer";
        for id in registry::CIPHER_ORDER {
            let composed = compose(
                cover.clone(),
                secret.to_string(),
                vec!["zero_width".to_string()],
                Some(id.to_string()),
                Some("correct horse battery staple".to_string()),
                false,
                false,
            )
            .unwrap_or_else(|e| panic!("cipher {id} must compose: {e}"));
            assert_eq!(composed.cipher.as_deref(), Some(id));

            let revealed = reveal(
                composed.stego_text,
                Some("zero_width".to_string()),
                Some("correct horse battery staple".to_string()),
            )
            .unwrap_or_else(|e| panic!("cipher {id} must reveal: {e}"));
            assert_eq!(revealed.hidden_text.as_deref(), Some(secret));
            assert_eq!(revealed.cipher_used.as_deref(), Some(id));
        }
    }

    #[test]
    fn a_cipher_without_a_passphrase_is_refused() {
        let error = compose(
            long_cover(),
            "no passphrase given".to_string(),
            vec!["zero_width".to_string()],
            Some("aes256_gcm".to_string()),
            Some(String::new()),
            false,
            false,
        )
        .expect_err("an empty passphrase must not silently disable encryption");
        assert!(error.contains("aes256_gcm"), "the error must name the cipher: {error}");
    }

    #[test]
    fn measured_payload_matches_the_composed_layer() {
        let cover = long_cover();
        let secret = "size check";
        let measured = measure_payload(secret.to_string(), None, None).expect("measurement");
        let composed = compose(
            cover,
            secret.to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .expect("composition");
        assert_eq!(measured.bits, composed.layer_bits);
    }

    #[test]
    fn carrier_capacity_marks_only_the_overflowing_carrier() {
        let report = carrier_capacity(long_cover(), false);
        assert_eq!(report.len(), registry::CARRIER_ORDER.len());
        for entry in &report {
            if entry.id == "zero_width" {
                assert!(entry.accepts_overflow, "zero_width accepts overflow by design");
            } else {
                assert!(
                    !entry.accepts_overflow,
                    "carrier {} enforces its capacity",
                    entry.id
                );
            }
            assert!(entry.bits > 0, "carrier {} must report capacity", entry.id);
        }
    }

    // ─── Mission-gated capacity (backlog UI-mission / E3) ───

    #[test]
    fn each_mission_reports_its_recommended_ceiling_and_effective_capacity() {
        let cover = long_cover();
        // recommended, range min, range max, per SPEC_CORE_V2 §5.3.
        let expectations = [
            ("conceal", 0.25_f64, 0.05_f64, 0.60_f64),
            ("sign", 0.50, 0.10, 0.90),
            ("mark", 0.85, 0.20, 1.00),
        ];
        // The narrowest carrier over the registry is the response's basis when
        // no selection is passed.
        let narrowest = registry::all_carriers()
            .iter()
            .map(|method| method.positions(&cover))
            .min()
            .expect("the registry holds carriers");

        for (id, recommended, min_d, max_d) in expectations {
            let response = mission_capacity(MissionCapacityRequest {
                cover: cover.clone(),
                carriers: Vec::new(),
                mission: id.to_string(),
                density: None,
                secret: None,
                cipher: None,
                password: None,
                robust: false,
            })
            .unwrap_or_else(|e| panic!("mission {id} must report capacity: {e}"));

            assert_eq!(response.mission, id);
            assert_eq!(
                response.recommended_density, recommended,
                "the recommended ceiling is the core's ceiling_for"
            );
            assert_eq!(
                response.density, recommended,
                "the slider defaults to the mission's recommended value"
            );
            assert_eq!((response.min_density, response.max_density), (min_d, max_d));
            assert_eq!(response.positions, narrowest);
            let expected = ((narrowest as f64) * recommended / 8.0).floor() as usize;
            assert_eq!(
                response.effective_capacity_bytes, expected,
                "effective capacity is floor(positions * density / 8), SPEC §5.3"
            );
            assert!(response.fits.is_none(), "no secret means no produced document");
            assert!(response.verdict.is_none());
        }
    }

    #[test]
    fn a_payload_fits_at_mark_but_overflows_at_conceal_by_named_arithmetic() {
        // F19b through the interface: the same secret the unbounded carrier
        // carries at Mark is refused at Conceal, by the core's named arithmetic
        // and not a silent truncation.
        let cover = corpus("en_short.txt");
        let secret = "a payload the short cover cannot conceal without overflowing";

        let mark = mission_capacity(MissionCapacityRequest {
            cover: cover.clone(),
            carriers: vec!["zero_width".to_string()],
            mission: "mark".to_string(),
            density: None,
            secret: Some(secret.to_string()),
            cipher: None,
            password: None,
            robust: false,
        })
        .expect("Mark reports its produced document");
        assert_eq!(mark.fits, Some(true), "Mark allows the overflow past the cover");
        assert!(mark.verdict.is_some(), "an accepted document carries a measured verdict");
        assert!(mark.noise_density.unwrap_or(0.0) > 0.0, "the channel is measured, not zero");

        let conceal = mission_capacity(MissionCapacityRequest {
            cover,
            carriers: vec!["zero_width".to_string()],
            mission: "conceal".to_string(),
            density: None,
            secret: Some(secret.to_string()),
            cipher: None,
            password: None,
            robust: false,
        })
        .expect("Conceal returns a refusal report, not an error");
        assert_eq!(conceal.fits, Some(false), "Conceal refuses to overflow its ceiling");
        let needed = conceal.needed_bits.expect("the refusal names what was needed");
        let available = conceal.available_bits.expect("the refusal names the budget");
        assert!(
            needed > available,
            "the payload ({needed} bits) is past the Conceal budget ({available} bits)"
        );
        assert!(conceal.verdict.is_none(), "a refused mission produced no document to judge");
    }

    #[test]
    fn the_reported_verdict_is_the_one_forensic_returns_on_the_produced_document() {
        let cover = long_cover();
        let secret = "a provenance layer a mark carries in full";
        let response = mission_capacity(MissionCapacityRequest {
            cover: cover.clone(),
            carriers: vec!["zero_width".to_string()],
            mission: "mark".to_string(),
            density: None,
            secret: Some(secret.to_string()),
            cipher: None,
            password: None,
            robust: false,
        })
        .expect("Mark composes");
        assert_eq!(response.fits, Some(true));

        // Produced independently from the same inputs: the verdict the command
        // reports is exactly the one forensic returns on such a document, and the
        // density is exactly the one metrics measures. Both are salt-invariant for
        // a decodable layer, so an independent encode reaches the same figures.
        let zw = registry::carrier("zero_width").expect("carrier");
        let produced = pipeline::encode_for_mission(
            &cover,
            secret.as_bytes(),
            &[zw.as_ref()],
            None,
            Some(format::Mission::Mark),
        )
        .expect("independent encode");
        let expected_verdict = forensic::analyze(&produced.stego_text).verdict.to_string();
        assert_eq!(
            response.verdict.as_deref(),
            Some(expected_verdict.as_str()),
            "the verdict is the analyser's own, measured on the produced document"
        );
        assert_eq!(
            response.noise_density,
            Some(metrics::noise_density(&produced.stego_text)),
            "the density is the one metrics returns on the produced document"
        );
    }

    #[test]
    fn the_density_slider_scales_the_effective_capacity_and_clamps_to_range() {
        let cover = long_cover();
        let at = |density: f64| {
            mission_capacity(MissionCapacityRequest {
                cover: cover.clone(),
                carriers: vec!["zero_width".to_string()],
                mission: "sign".to_string(),
                density: Some(density),
                secret: None,
                cipher: None,
                password: None,
                robust: false,
            })
            .expect("Sign reports capacity at any fill ratio")
        };

        let low = at(0.10);
        let high = at(0.90);
        assert_eq!(low.density, 0.10);
        assert_eq!(high.density, 0.90);
        assert!(
            high.effective_capacity_bytes > low.effective_capacity_bytes,
            "a higher fill ratio budgets more capacity"
        );

        // A value past the mission range is clamped to the endpoint, never
        // applied raw: Sign tops out at 0.90 (SPEC §5.3).
        let over = at(5.0);
        assert_eq!(over.density, 0.90, "the fill ratio is clamped to the mission range");
    }

    #[test]
    fn an_unknown_mission_is_refused_by_name() {
        let error = mission_capacity(MissionCapacityRequest {
            cover: long_cover(),
            carriers: Vec::new(),
            mission: "vanish".to_string(),
            density: None,
            secret: None,
            cipher: None,
            password: None,
            robust: false,
        })
        .expect_err("an unknown mission id is refused");
        assert!(error.contains("vanish"), "the refusal names the unknown mission: {error}");
    }

    #[test]
    fn compare_refuses_a_missing_side() {
        assert!(compute_metrics(String::new(), "text".to_string()).is_err());
        assert!(compute_metrics("text".to_string(), String::new()).is_err());
        assert!(compute_metrics("a b c".to_string(), "a b c".to_string()).is_ok());
    }

    #[test]
    fn inspecting_a_composed_text_confirms_it() {
        let composed = compose(
            long_cover(),
            "found me".to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .expect("composition");
        let report = forensic_analyze(composed.stego_text).expect("inspection");
        assert_eq!(report.verdict, forensic::Verdict::Confirmed);
        assert!(!report.stego_signatures.is_empty());
    }

    fn corpus(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("corpus")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("corpus document {} is missing: {e}", path.display()))
    }

    /// The pre-flight capacity the interface shows is the figure the compose
    /// step accepts. On technical_markdown.md the substitution carrier reported
    /// zero under the heavy frame, not the raw sixty; under the light frame
    /// default (§3.2) this short cover now carries a real secret, and a secret
    /// one byte past the reported figure is still refused. The carrier the cover
    /// does not bound is marked as such rather than shown a misleading number.
    #[test]
    fn the_pre_flight_capacity_is_the_one_compose_accepts() {
        let cover = corpus("technical_markdown.md");
        let report = carrier_capacity(cover.clone(), false);

        let homoglyph = report
            .iter()
            .find(|c| c.id == "homoglyph")
            .expect("homoglyph is reported");
        assert!(homoglyph.bits > 8, "the cover has raw positions to spare");
        assert!(
            homoglyph.secret_bytes > 0,
            "the light frame default makes this short cover usable, not the heavy zero"
        );

        for entry in &report {
            if !entry.cover_bounds_writes {
                assert_eq!(entry.id, "zero_width");
                continue;
            }
            if entry.secret_bytes > 0 {
                let placed = compose(
                    cover.clone(),
                    "x".repeat(entry.secret_bytes),
                    vec![entry.id.clone()],
                    None,
                    None,
                    false,
                    false,
                );
                assert!(
                    placed.is_ok(),
                    "{}: the reported {} bytes must be accepted",
                    entry.id,
                    entry.secret_bytes
                );
            }
            let over = compose(
                cover.clone(),
                "x".repeat(entry.secret_bytes + 1),
                vec![entry.id.clone()],
                None,
                None,
                false,
                false,
            );
            assert!(
                over.is_err(),
                "{}: one byte past secret_bytes must be refused",
                entry.id
            );
        }
    }

    /// A document too small for any frame: every bounded carrier reports zero and
    /// refuses a one byte secret, while the carrier the cover does not bound is
    /// marked as unbounded rather than as having a zero limit.
    #[test]
    fn a_document_too_small_reports_zero_for_the_bounded_carriers() {
        let cover = corpus("minimal_tiny.txt");
        let report = carrier_capacity(cover.clone(), false);
        for entry in &report {
            if entry.cover_bounds_writes {
                assert_eq!(
                    entry.secret_bytes, 0,
                    "{}: this cover frames nothing",
                    entry.id
                );
                let attempt = compose(
                    cover.clone(),
                    "x".to_string(),
                    vec![entry.id.clone()],
                    None,
                    None,
                    false,
                    false,
                );
                assert!(
                    attempt.is_err(),
                    "{}: a bounded carrier reporting zero must refuse a one byte secret",
                    entry.id
                );
            }
        }
    }

    // ─── Traced reveal ──────────────────────────────────────

    #[test]
    fn a_clean_traced_reveal_returns_its_waves_in_reverse_order() {
        let cover = long_cover();
        let secret = "trace in reverse";
        let composed = compose(
            cover,
            secret.to_string(),
            vec!["zero_width".to_string()],
            None,
            None,
            false,
            false,
        )
        .expect("composition");

        let response = reveal_traced(composed.stego_text, None, false).expect("traced reveal");
        assert!(response.recovered, "a clean document must recover");
        assert_eq!(response.hidden_text.as_deref(), Some(secret));
        assert!(!response.recovery_used, "a headed document uses the standard pass");
        assert!(!response.recovery_available);
        assert!(response.integrity, "an exact checksum verifies the payload");

        // Strict reverse encode order: identify, then the carrier layer, then the
        // envelope, then the transform chain reversed, here just the integrity step.
        let categories: Vec<&str> = response.waves.iter().map(|w| w.category.as_str()).collect();
        assert_eq!(categories, vec!["identify", "carrier", "envelope", "integrity"]);
    }

    #[test]
    fn an_exact_oracle_verdict_is_carried_through() {
        let cover = long_cover();
        let secret = "authenticated layer";
        // An authenticated cipher: its wave is judged by the level-1 tag.
        let composed = compose(
            cover,
            secret.to_string(),
            vec!["zero_width".to_string()],
            Some("aes256_gcm".to_string()),
            Some("correct horse battery staple".to_string()),
            false,
            false,
        )
        .expect("composition");

        let response = reveal_traced(
            composed.stego_text,
            Some("correct horse battery staple".to_string()),
            false,
        )
        .expect("traced reveal");
        assert!(response.recovered);
        assert!(response.integrity);

        let confidentiality = response
            .waves
            .iter()
            .find(|w| w.category == "confidentiality")
            .expect("a cipher wave must be present");
        assert_eq!(confidentiality.oracle, "aead_tag", "level 1 is exact");
        assert_eq!(confidentiality.verdict, "passed");

        // The envelope is a structural step, judged by nothing on its own: an
        // exact verdict must never be invented for it.
        let envelope = response
            .waves
            .iter()
            .find(|w| w.category == "envelope")
            .expect("an envelope wave must be present");
        assert_eq!(envelope.oracle, "none");
        assert_eq!(envelope.verdict, "passed");
    }

    #[test]
    fn a_corrupted_layer_names_the_wave_that_failed() {
        let cover = long_cover();
        let secret = "wrong key halts here";
        let composed = compose(
            cover,
            secret.to_string(),
            vec!["zero_width".to_string()],
            Some("aes256_gcm".to_string()),
            Some("the right passphrase".to_string()),
            false,
            false,
        )
        .expect("composition");

        // The document is intact, but the passphrase is wrong: the cipher wave is
        // the one that cannot keep its promise, and the trace must name it.
        let response = reveal_traced(
            composed.stego_text,
            Some("the wrong passphrase".to_string()),
            false,
        )
        .expect("a traced reveal still returns its trace on failure");
        assert!(!response.recovered, "a wrong key recovers nothing");
        assert!(response.error.is_some(), "the failure is named, not swallowed");

        let failed = response.failed_step.clone().expect("a failed wave must be named");
        let wave = response
            .waves
            .iter()
            .find(|w| w.step == failed)
            .expect("the named wave is in the trace");
        assert_eq!(wave.category, "confidentiality");
        assert_eq!(wave.verdict, "failed");
        assert_eq!(wave.oracle, "aead_tag");
        assert!(wave.reason.is_some(), "a failed wave carries its reason");

        // Every wave before the failure passed: a failure is a location, not a
        // generic error.
        assert!(response
            .waves
            .iter()
            .take_while(|w| w.step != failed)
            .all(|w| w.verdict == "passed"));
    }

    #[test]
    fn recovery_is_only_entered_when_asked() {
        // Plain text carries no layer, so a standard pass finds no header.
        let plain = long_cover();

        // Recovery not authorised: the sweep's outcome is not surfaced, the
        // control is offered instead, and no recovery wave appears in the trace.
        let standard = reveal_traced(plain.clone(), None, false).expect("standard pass");
        assert!(!standard.recovered);
        assert!(standard.recovery_available, "the control is offered");
        assert!(!standard.recovery_used);
        assert!(
            standard.waves.iter().all(|w| w.category != "recovery"),
            "the sweep is not surfaced until it is asked for"
        );

        // Recovery authorised: the declared sweep runs and names itself. Nothing
        // is found, which is undetermined, not a failure.
        let recovered = reveal_traced(plain, None, true).expect("recovery pass");
        assert!(!recovered.recovered);
        assert!(recovered.recovery_used, "the sweep ran and is named");
        let sweep = recovered
            .waves
            .iter()
            .find(|w| w.category == "recovery")
            .expect("the recovery sweep is in the trace");
        assert_eq!(sweep.verdict, "undetermined", "nothing found is undetermined");
        assert!(sweep.reason.is_some());
        assert!(recovered.failed_step.is_none(), "undetermined is not a failure");
    }

    #[test]
    fn a_binary_payload_is_reported_as_bytes_not_text() {
        // A payload that is not valid UTF-8 must be reported by size, never forced
        // into a text field.
        let cover = long_cover();
        let carrier = registry::carrier("zero_width").expect("carrier");
        let composed = stegano_core::pipeline::encode(
            &cover,
            &[0xFF, 0xFE, 0x00, 0x01],
            &[carrier.as_ref()],
            None,
        )
        .expect("a raw byte payload composes");

        let response = reveal_traced(composed.stego_text, None, false).expect("traced reveal");
        assert!(response.recovered);
        assert_eq!(response.hidden_size_bytes, Some(4));
        assert!(response.hidden_text.is_none(), "a binary payload is not shown as text");
    }

    // ─── File conceal (in-place, same-format) ───────────────

    #[test]
    fn file_conceal_marks_a_text_native_cover_and_the_bytes_re_decode() {
        // A Markdown cover accepts a concealed secret in place; the marked bytes
        // are the real, larger document, and the returned bytes both re-inspect as
        // marked and decode back to the exact secret.
        let cover = long_cover();
        let secret = "hidden inside a file";
        let response = file_conceal(FileConcealRequest {
            bytes: cover.clone().into_bytes(),
            format: "md".to_string(),
            secret: secret.to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: None,
            password: None,
            saturate: false,
        })
        .expect("a Markdown cover must accept a concealed secret");

        // The conceal really altered the document: the bytes differ and grew, and
        // every size is measured, not asserted.
        assert_ne!(response.bytes, cover.as_bytes(), "the conceal must alter the document");
        assert_eq!(response.source_len, cover.len());
        assert_eq!(response.marked_len, response.bytes.len());
        assert!(response.marked_len > response.source_len, "channel characters were added");
        assert_eq!(response.secret_len, secret.len());
        assert_eq!(response.carriers, vec!["zero_width".to_string()]);
        assert!(response.cipher.is_none());
        assert_eq!(response.format, "markdown", "the output keeps the source format");

        // The returned bytes re-inspect as marked: the tool's own file inspector,
        // run on the marked bytes, sees the mark.
        let report = file_inspect(FileInspectRequest {
            bytes: response.bytes.clone(),
            format: "md".to_string(),
        })
        .expect("the marked file must inspect");
        assert!(
            report.suspicion_score > 0.0 || !report.carrier_signatures.is_empty(),
            "the marked file must inspect as carrying a mark"
        );

        // And the marked text decodes back to the exact secret, with integrity.
        let marked_text = response
            .marked_text
            .expect("a text-native conceal returns the marked text");
        let revealed = reveal(marked_text, Some("zero_width".to_string()), None)
            .expect("the marked text must reveal");
        assert_eq!(revealed.hidden_text.as_deref(), Some(secret));
        assert!(revealed.integrity, "an exact checksum verifies the payload");
    }

    #[test]
    fn file_conceal_with_a_cipher_round_trips_and_names_the_cipher() {
        // A generous cover: the encrypted envelope (nonce, tag) is larger than the
        // plain layer, so the conceal needs more room under the concealment ceiling.
        let cover = PROBE_SENTENCE.repeat(120);
        let secret = "top secret in a file";
        let passphrase = "correct horse battery staple";
        let response = file_conceal(FileConcealRequest {
            bytes: cover.into_bytes(),
            format: "md".to_string(),
            secret: secret.to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: Some("chacha20_poly1305".to_string()),
            password: Some(passphrase.to_string()),
            saturate: false,
        })
        .expect("an encrypted conceal must succeed");
        assert_eq!(response.cipher.as_deref(), Some("chacha20_poly1305"));

        let marked = response.marked_text.expect("marked text present");
        let revealed = reveal(marked, Some("zero_width".to_string()), Some(passphrase.to_string()))
            .expect("the encrypted layer must reveal with the passphrase");
        assert_eq!(revealed.hidden_text.as_deref(), Some(secret));
        assert_eq!(revealed.cipher_used.as_deref(), Some("chacha20_poly1305"));
    }

    #[test]
    fn file_conceal_into_a_non_text_native_cover_is_refused_by_name() {
        // Concealing into HTML is refused BY NAME: the globally placed marked text
        // cannot be proven redistributed across the document's nodes in this build,
        // and a silent partial is worse than a named refusal (invariant 2).
        let html = b"<html><body><p>Body text here to host a secret.</p></body></html>".to_vec();
        let error = file_conceal(FileConcealRequest {
            bytes: html,
            format: "html".to_string(),
            secret: "secret".to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: None,
            password: None,
            saturate: false,
        })
        .expect_err("concealing into HTML must be refused");
        assert!(error.contains("HTML"), "the refusal must name the format: {error}");
    }

    #[test]
    fn file_conceal_with_an_empty_secret_is_refused_by_name() {
        let cover = long_cover();
        let error = file_conceal(FileConcealRequest {
            bytes: cover.into_bytes(),
            format: "md".to_string(),
            secret: String::new(),
            carriers: vec!["zero_width".to_string()],
            cipher: None,
            password: None,
            saturate: false,
        })
        .expect_err("an empty secret must be refused, not silently produce a file");
        assert!(
            error.contains("nothing to hide"),
            "the engine's named refusal must surface: {error}"
        );
    }

    #[test]
    fn file_conceal_with_a_cipher_and_no_passphrase_is_refused_by_name() {
        let cover = long_cover();
        let error = file_conceal(FileConcealRequest {
            bytes: cover.into_bytes(),
            format: "md".to_string(),
            secret: "needs a passphrase".to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: Some("aes256_gcm".to_string()),
            password: Some(String::new()),
            saturate: false,
        })
        .expect_err("a cipher with an empty passphrase must not silently disable encryption");
        assert!(error.contains("aes256_gcm"), "the error must name the cipher: {error}");
    }

    #[test]
    fn file_conceal_of_a_secret_too_large_is_refused_by_named_arithmetic() {
        // A tiny cover cannot hold the secret under the concealment ceiling, so the
        // core refuses with named arithmetic rather than overflowing (invariant 2,
        // invariant 4b), surfaced through the file layer, never a truncation.
        let error = file_conceal(FileConcealRequest {
            bytes: b"A short note.".to_vec(),
            format: "md".to_string(),
            secret: "this secret is far larger than such a tiny cover can ever conceal".to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: None,
            password: None,
            saturate: false,
        })
        .expect_err("a secret too large for the cover must be refused");
        assert!(!error.is_empty(), "the refusal names itself, never a silent result");
    }

    // ─── File decode (in-place, same-format) ────────────────

    #[test]
    fn file_decode_recovers_a_hidden_secret_from_a_text_native_file() {
        // A Markdown cover concealed a secret in place; decoding the marked file
        // reads its text and runs the SAME reveal path the text decode runs,
        // recovering the exact secret with integrity. The file decode owns no
        // decode logic: it only reaches the layer from a file.
        let cover = long_cover();
        let secret = "hidden inside a file";
        let marked = file_conceal(FileConcealRequest {
            bytes: cover.into_bytes(),
            format: "md".to_string(),
            secret: secret.to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: None,
            password: None,
            saturate: false,
        })
        .expect("a Markdown cover accepts a concealed secret");

        let decoded = file_decode(FileDecodeRequest {
            bytes: marked.bytes,
            format: "md".to_string(),
            password: None,
            carrier: Some("zero_width".to_string()),
        })
        .expect("the marked file must decode");
        assert_eq!(decoded.hidden_text.as_deref(), Some(secret));
        assert_eq!(decoded.hidden_size_bytes, secret.len());
        assert!(decoded.integrity, "an exact checksum verifies the recovered layer");
    }

    #[test]
    fn file_decode_of_an_encrypted_layer_round_trips_with_the_passphrase() {
        // The passphrase reaches the same cascade the text path uses: an encrypted
        // layer concealed in a file recovers with its passphrase and names the
        // cipher, exactly as a pasted text would.
        let cover = PROBE_SENTENCE.repeat(120);
        let secret = "top secret in a file";
        let passphrase = "correct horse battery staple";
        let marked = file_conceal(FileConcealRequest {
            bytes: cover.into_bytes(),
            format: "md".to_string(),
            secret: secret.to_string(),
            carriers: vec!["zero_width".to_string()],
            cipher: Some("chacha20_poly1305".to_string()),
            password: Some(passphrase.to_string()),
            saturate: false,
        })
        .expect("an encrypted conceal must succeed");

        let decoded = file_decode(FileDecodeRequest {
            bytes: marked.bytes,
            format: "md".to_string(),
            password: Some(passphrase.to_string()),
            carrier: Some("zero_width".to_string()),
        })
        .expect("the encrypted file must decode with the passphrase");
        assert_eq!(decoded.hidden_text.as_deref(), Some(secret));
        assert_eq!(decoded.cipher_used.as_deref(), Some("chacha20_poly1305"));
        assert!(decoded.integrity);
    }

    #[test]
    fn file_decode_recovers_a_hidden_file_from_a_marked_document() {
        // The concealed layer can itself carry an attached file. Decoding the
        // marked document recovers the layer, and the SAME recover path the Decode
        // tab already uses reads the attached file back, byte for byte. The bytes
        // are the engine's real output, never fabricated.
        let cover = PROBE_SENTENCE.repeat(400);
        let payload = b"the contents of a small hidden file".to_vec();
        let attached = attach_payload(String::new(), "note.bin".to_string(), payload.clone())
            .expect("a small file attaches to the layer");
        let marked = file_conceal(FileConcealRequest {
            bytes: cover.into_bytes(),
            format: "md".to_string(),
            secret: attached.text,
            carriers: vec!["zero_width".to_string()],
            cipher: None,
            password: None,
            saturate: false,
        })
        .expect("the cover carries the attached-file layer");

        let decoded = file_decode(FileDecodeRequest {
            bytes: marked.bytes,
            format: "md".to_string(),
            password: None,
            carrier: Some("zero_width".to_string()),
        })
        .expect("the marked file decodes");
        let layer = decoded
            .hidden_text
            .expect("the recovered layer is text carrying a file");
        let recovered = recover_attachments(layer).expect("the layer lists its file");
        assert_eq!(recovered.count, 1);
        assert_eq!(recovered.files[0].filename, "note.bin");
        assert_eq!(
            recovered.files[0].data, payload,
            "the recovered bytes are identical to the original"
        );
    }

    #[test]
    fn file_decode_of_a_plain_file_reports_no_layer_by_name() {
        // A plain Markdown file carries no hidden layer. Decoding it does not
        // fabricate an empty result: the decode cascade's own NAMED failure
        // surfaces through reveal (invariant 2), never a silent empty.
        let plain = long_cover();
        let error = file_decode(FileDecodeRequest {
            bytes: plain.into_bytes(),
            format: "md".to_string(),
            password: None,
            carrier: None,
        })
        .expect_err("a file with no layer must be refused, not silently empty");
        assert!(
            error.contains("detected"),
            "the engine's named 'nothing detected' refusal must surface: {error}"
        );
    }

    #[test]
    fn file_decode_refuses_an_unreadable_file_by_name() {
        // Bytes that are not a real DOCX cannot yield text; the file layer refuses
        // by name (naming the format) rather than decoding an empty document
        // (invariant 2), and file_decode surfaces that named error unchanged.
        let error = file_decode(FileDecodeRequest {
            bytes: b"not a real document".to_vec(),
            format: "docx".to_string(),
            password: None,
            carrier: None,
        })
        .expect_err("an unreadable document must be refused");
        assert!(error.contains("DOCX"), "the refusal names the format: {error}");
    }

    #[test]
    fn file_decode_refuses_an_unknown_format_by_name() {
        let error = file_decode(FileDecodeRequest {
            bytes: b"anything".to_vec(),
            format: "pdf".to_string(),
            password: None,
            carrier: None,
        })
        .expect_err("an unsupported format must be refused");
        assert!(error.contains("pdf"), "the refusal names the format: {error}");
    }

    // ─── Provenance ─────────────────────────────────────────

    use stegano_core::provenance::RobustnessClass;

    #[test]
    fn the_identity_helper_mints_a_usable_keypair() {
        let identity = generate_signing_identity();
        assert_eq!(identity.algorithm, "ed25519");
        assert_eq!(identity.public_key.len(), 64, "an Ed25519 public key is 32 bytes");
        assert_eq!(identity.private_key.len(), 64, "an Ed25519 private key is 32 bytes");
        assert_ne!(identity.public_key, identity.private_key);

        // The minted key actually signs: a detached mark by it names it as signer.
        let marked = provenance_mark(MarkRequest {
            cover: "A sentence long enough to carry a detached claim beside it.".to_string(),
            assertions: AssertionSelection {
                human_authorship: true,
                ..Default::default()
            },
            private_key: identity.private_key.clone(),
            binding: "detached".to_string(),
            carrier: None,
            created: None,
        })
        .expect("a detached mark must succeed");
        assert_eq!(marked.signer_public_key, identity.public_key);
    }

    #[test]
    fn a_detached_mark_verifies_as_trusted_and_unaltered() {
        let identity = generate_signing_identity();
        let cover = "The report was finalised on Tuesday and signed the same afternoon.".to_string();
        let marked = provenance_mark(MarkRequest {
            cover: cover.clone(),
            assertions: AssertionSelection {
                human_authorship: true,
                author: Some("Ada".to_string()),
                integrity: true,
                ..Default::default()
            },
            private_key: identity.private_key.clone(),
            binding: "detached".to_string(),
            carrier: None,
            created: Some("2026-08-20T09:00:00Z".to_string()),
        })
        .expect("mark must succeed");
        assert_eq!(marked.declared_robustness.class, RobustnessClass::High);
        let sidecar = marked.sidecar.expect("a detached mark yields a sidecar");

        let report = provenance_verify(VerifyRequest {
            document: cover,
            sidecar: Some(sidecar),
            trusted_keys: vec![identity.public_key.clone()],
            carriers: vec![],
        })
        .expect("verify must succeed");
        assert_eq!(report.claims.len(), 1);
        let claim = &report.claims[0];
        assert_eq!(claim.binding, "detached");
        assert!(claim.signature_valid);
        assert!(claim.signer_trusted);
        assert!(claim.document_unaltered);
        assert!(claim.has_kind("human_authorship"));
        assert!(claim.has_kind("integrity"));
        assert_eq!(report.strongest, Some(0));
    }

    #[test]
    fn a_tampered_document_is_reported_altered_by_name() {
        let identity = generate_signing_identity();
        let cover = "The clause stands exactly as written.".to_string();
        let marked = provenance_mark(MarkRequest {
            cover: cover.clone(),
            assertions: AssertionSelection {
                human_authorship: true,
                ..Default::default()
            },
            private_key: identity.private_key.clone(),
            binding: "detached".to_string(),
            carrier: None,
            created: None,
        })
        .expect("mark");
        let sidecar = marked.sidecar.unwrap();

        let altered = format!("{cover} And one sentence that was not there.");
        let report = provenance_verify(VerifyRequest {
            document: altered,
            sidecar: Some(sidecar),
            trusted_keys: vec![identity.public_key.clone()],
            carriers: vec![],
        })
        .expect("verify");
        let claim = &report.claims[0];
        assert!(!claim.document_unaltered, "the document was altered");
        assert!(
            claim.findings.iter().any(|f| f.contains("altered")),
            "a finding must name the alteration: {:?}",
            claim.findings
        );
        assert_eq!(report.strongest, None, "an altered document is not the strongest claim");
    }

    #[test]
    fn an_in_band_mark_round_trips_and_reports_measured_robustness() {
        let identity = generate_signing_identity();
        let cover = long_cover();
        let marked = provenance_mark(MarkRequest {
            cover: cover.clone(),
            assertions: AssertionSelection {
                ai_generated: true,
                model: Some("a-model".to_string()),
                provider: Some("a-provider".to_string()),
                ..Default::default()
            },
            private_key: identity.private_key.clone(),
            binding: "in_band".to_string(),
            carrier: Some("zero_width".to_string()),
            created: None,
        })
        .expect("an in-band mark must succeed");
        assert_eq!(marked.cover_restored, Some(true), "the mark must strip back to the cover");
        assert_eq!(marked.declared_robustness.class, RobustnessClass::BestEffort);
        let measured = marked
            .measured_robustness
            .expect("an in-band mark reports a measured robustness");
        assert_eq!(measured.class, RobustnessClass::BestEffort);
        let document = marked.marked_text.expect("an in-band mark yields marked text");

        let report = provenance_verify(VerifyRequest {
            document,
            sidecar: None,
            trusted_keys: vec![identity.public_key.clone()],
            carriers: vec!["zero_width".to_string()],
        })
        .expect("verify");
        assert_eq!(report.claims.len(), 1);
        let claim = &report.claims[0];
        assert_eq!(claim.binding, "in_band");
        assert!(claim.signature_valid && claim.document_unaltered && claim.signer_trusted);
        assert!(claim.has_kind("ai_generated"));
        assert_eq!(claim.robustness_realised.class, RobustnessClass::BestEffort);
    }

    #[test]
    fn an_in_band_mark_on_a_tiny_cover_names_the_capacity_refusal() {
        let identity = generate_signing_identity();
        let error = provenance_mark(MarkRequest {
            cover: "ok thanks".to_string(),
            assertions: AssertionSelection {
                human_authorship: true,
                ..Default::default()
            },
            private_key: identity.private_key.clone(),
            binding: "in_band".to_string(),
            carrier: Some("homoglyph".to_string()),
            created: None,
        })
        .expect_err("a tiny cover cannot hold a whole signed claim in-band");
        assert!(
            error.contains("Capacity exceeded"),
            "the refusal must name the arithmetic, not truncate: {error}"
        );
    }

    #[test]
    fn a_mark_with_no_assertion_is_refused_by_name() {
        let identity = generate_signing_identity();
        let error = provenance_mark(MarkRequest {
            cover: "some cover text with room to spare".to_string(),
            assertions: AssertionSelection::default(),
            private_key: identity.private_key.clone(),
            binding: "detached".to_string(),
            carrier: None,
            created: None,
        })
        .expect_err("no assertion is not a claim");
        assert!(error.contains("at least one assertion"));
    }

    #[test]
    fn a_claim_signed_by_an_untrusted_key_is_present_but_untrusted() {
        let signer = generate_signing_identity();
        let other = generate_signing_identity();
        let cover = "A statement a stranger did not sign.".to_string();
        let marked = provenance_mark(MarkRequest {
            cover: cover.clone(),
            assertions: AssertionSelection {
                human_authorship: true,
                ..Default::default()
            },
            private_key: signer.private_key.clone(),
            binding: "detached".to_string(),
            carrier: None,
            created: None,
        })
        .expect("mark");

        let report = provenance_verify(VerifyRequest {
            document: cover,
            sidecar: marked.sidecar,
            trusted_keys: vec![other.public_key.clone()],
            carriers: vec![],
        })
        .expect("verify");
        let claim = &report.claims[0];
        assert!(claim.signature_valid, "the signature itself is valid");
        assert!(!claim.signer_trusted, "but the signer is not trusted");
        assert!(
            claim.findings.iter().any(|f| f.contains("not trusted")),
            "a finding must name the untrusted signer: {:?}",
            claim.findings
        );
        assert_eq!(report.strongest, None);
    }

    #[test]
    fn verify_names_an_unreadable_trusted_key() {
        let error = provenance_verify(VerifyRequest {
            document: "a document to verify".to_string(),
            sidecar: None,
            trusted_keys: vec!["not a real key".to_string()],
            carriers: vec![],
        })
        .expect_err("an unreadable trusted key must be named");
        assert!(!error.is_empty(), "the error must say something");
    }

    // ─── Canary trap ────────────────────────────────────────────

    #[test]
    fn a_canary_batch_marks_each_recipient_and_strips_back() {
        let response = canary_generate(CanaryGenerateRequest {
            document: long_cover(),
            recipients: vec![
                "alice@lab.test".to_string(),
                "bob@lab.test".to_string(),
                "carol@lab.test".to_string(),
            ],
            salt: "quarterly-2026".to_string(),
        })
        .expect("generation must succeed");

        assert_eq!(response.recipient_count, 3);
        assert_eq!(response.versions.len(), 3);
        assert!(response.fingerprint_bits > 0, "a markable cover has capacity");
        assert!(
            response.cover_restored,
            "every version must strip back to the exact document"
        );

        // Each recipient gets a distinct fingerprint and a distinct marked text.
        let texts: Vec<&str> = response.versions.iter().map(|v| v.text.as_str()).collect();
        assert_ne!(texts[0], texts[1]);
        assert_ne!(texts[1], texts[2]);
        let hexes: Vec<&str> = response
            .versions
            .iter()
            .map(|v| v.fingerprint_hex.as_str())
            .collect();
        assert_ne!(hexes[0], hexes[1]);

        // The registry the operator saves parses back into recipients.
        let registry: CanaryRegistry =
            serde_json::from_str(&response.registry).expect("registry must parse");
        assert_eq!(registry.recipients.len(), 3);
        assert_eq!(registry.salt, "quarterly-2026");
    }

    #[test]
    fn a_canary_leak_is_traced_to_its_recipient() {
        let batch = canary_generate(CanaryGenerateRequest {
            document: long_cover(),
            recipients: vec![
                "alice@lab.test".to_string(),
                "bob@lab.test".to_string(),
                "carol@lab.test".to_string(),
            ],
            salt: "secret-salt".to_string(),
        })
        .expect("generation must succeed");

        // Bob's copy leaks, verbatim.
        let leaked = batch.versions[1].text.clone();
        let outcome = canary_trace(CanaryTraceRequest {
            leaked_text: leaked,
            registry: batch.registry.clone(),
        })
        .expect("trace must succeed");

        assert_eq!(outcome.matched_recipient.as_deref(), Some("bob@lab.test"));
        assert_eq!(outcome.confidence, 1.0);
        assert_eq!(outcome.recipient_count, 3);
        // The extracted fingerprint matches the version the leak came from.
        assert_eq!(outcome.extracted_fingerprint_hex, batch.versions[1].fingerprint_hex);
    }

    #[test]
    fn a_canary_trace_on_the_plain_document_names_no_recipient() {
        let batch = canary_generate(CanaryGenerateRequest {
            document: long_cover(),
            recipients: vec!["alice@lab.test".to_string(), "bob@lab.test".to_string()],
            salt: "salt".to_string(),
        })
        .expect("generation must succeed");

        // The unmarked document carries no mark: no recipient, never a guess.
        let outcome = canary_trace(CanaryTraceRequest {
            leaked_text: long_cover(),
            registry: batch.registry,
        })
        .expect("trace must succeed");

        assert!(outcome.matched_recipient.is_none());
        assert_eq!(outcome.confidence, 0.0);
    }

    #[test]
    fn a_canary_generation_names_an_empty_document() {
        let error = canary_generate(CanaryGenerateRequest {
            document: "   ".to_string(),
            recipients: vec!["alice".to_string()],
            salt: "salt".to_string(),
        })
        .expect_err("an empty document must be refused by name");
        assert!(error.contains("document"), "the refusal must name the document: {error}");
    }

    #[test]
    fn a_canary_generation_needs_a_recipient() {
        let error = canary_generate(CanaryGenerateRequest {
            document: long_cover(),
            recipients: vec!["   ".to_string(), String::new()],
            salt: "salt".to_string(),
        })
        .expect_err("an empty recipient list must be refused by name");
        assert!(error.contains("recipient"), "the refusal must name the recipient: {error}");
    }

    #[test]
    fn a_canary_trace_names_an_unreadable_registry() {
        let error = canary_trace(CanaryTraceRequest {
            leaked_text: "some received text".to_string(),
            registry: "{ not a registry".to_string(),
        })
        .expect_err("an unreadable registry must be named");
        assert!(!error.is_empty(), "the error must say something");
    }

    // ─── AI-regulation ─────────────────────────────────────────

    const AI_REG_COVER: &str =
        "The quick brown fox jumps over the lazy dog, with plenty of words to carry a mark.";

    #[test]
    fn ai_regulation_inspect_reports_a_planted_mark() {
        use stegano_core::stego::ZeroWidth;
        let marked = ZeroWidth::new().encode(AI_REG_COVER, b"trace").unwrap();
        let report = document_inspect(DocumentInspectRequest { document: marked })
            .expect("a marked document inspects");
        let finding = report
            .classes
            .iter()
            .find(|c| c.id == "zero_width")
            .expect("the zero-width class is always listed");
        assert!(finding.count > 0, "the planted mark is seen");
    }

    #[test]
    fn ai_regulation_clean_removes_a_chosen_class_and_reports_residual() {
        use stegano_core::stego::ZeroWidth;
        let marked = ZeroWidth::new().encode(AI_REG_COVER, b"trace").unwrap();
        let report = document_clean(DocumentCleanRequest {
            document: marked,
            classes: vec!["zero_width".to_string()],
        })
        .expect("a marked document cleans");
        assert!(report.altered, "removing the planted class alters the text");
        assert!(
            report
                .removed
                .iter()
                .any(|r| r.id == "zero_width" && r.count > 0),
            "the removed count is reported for the chosen class"
        );
        assert!(
            !report.residual.is_empty(),
            "the honest residual note is always present"
        );
        assert_eq!(
            report.cleaned_text, AI_REG_COVER,
            "cleaning the only class present restores the exact cover"
        );
    }

    #[test]
    fn ai_regulation_clean_defaults_to_every_class_when_none_chosen() {
        use stegano_core::stego::ZeroWidth;
        let marked = ZeroWidth::new().encode(AI_REG_COVER, b"trace").unwrap();
        let report = document_clean(DocumentCleanRequest {
            document: marked,
            classes: Vec::new(),
        })
        .expect("an empty selection defaults to every class");
        assert_eq!(report.removed.len(), MarkClass::ALL.len());
        assert_eq!(report.cleaned_text, AI_REG_COVER);
    }

    #[test]
    fn ai_regulation_clean_refuses_an_unknown_class_by_name() {
        let error = document_clean(DocumentCleanRequest {
            document: "plain text".to_string(),
            classes: vec!["not_a_class".to_string()],
        })
        .expect_err("an unknown class id must be refused");
        assert!(
            error.contains("not_a_class"),
            "the refusal names the unknown class"
        );
    }

    #[test]
    fn ai_regulation_pristine_removes_invisibles_and_names_the_trade_off() {
        // A document carrying invisibles no cleanable class owns (a soft hyphen
        // among them). Pristine takes every invisible out and reports it.
        let report = document_pristine(DocumentPristineRequest {
            document: "a\u{200B}b\u{2063}c\u{00AD}d".to_string(),
        })
        .expect("a document with invisibles cleans to pristine");
        assert!(report.altered, "removing the invisibles alters the text");
        assert!(
            report.invisibles_removed >= 1,
            "the invisibles removed beyond the mark classes are counted"
        );
        assert!(
            !report.notes.is_empty(),
            "the honest trade-off note is always present"
        );
        assert!(
            !report
                .cleaned_text
                .chars()
                .any(|c| c.is_control() || matches!(c, '\u{200B}' | '\u{2063}' | '\u{00AD}')),
            "no invisible or format-control character is left"
        );
    }

    #[test]
    fn ai_regulation_pristine_refuses_an_empty_document_by_name() {
        let error = document_pristine(DocumentPristineRequest {
            document: String::new(),
        })
        .expect_err("an empty document must be refused");
        assert!(
            error.contains("empty"),
            "the refusal names the empty document"
        );
    }

    #[test]
    fn wordmark_analyze_command_names_the_wall() {
        let report = wordmark_analyze(WordmarkAnalyzeRequest {
            text: "plain ordinary sentences here".to_string(),
            acrostic_target: None,
            mark_key_hex: None,
        })
        .expect("a non-empty text is analyzed");
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f.verdict, stegano_wm::Verdict::Impossible)));
    }

    #[test]
    fn wordmark_scrub_command_perturbs_and_rejects_unknown_aggression() {
        let response = wordmark_scrub(WordmarkScrubRequest {
            text: "big fast help many keep whole".to_string(),
            aggression: Some("heavy".to_string()),
        })
        .expect("a heavy scrub runs");
        assert_eq!(response.positions_changed, 6);
        assert_ne!(response.text, "big fast help many keep whole");

        let error = wordmark_scrub(WordmarkScrubRequest {
            text: "big".to_string(),
            aggression: Some("nuclear".to_string()),
        })
        .expect_err("an unknown aggression is refused");
        assert!(error.contains("aggression"));
    }

    #[test]
    fn wordmark_rewrite_online_host_requires_the_disclaimer() {
        // An online host without the acknowledgment is refused by the gate
        // before any content leaves the machine, surfaced as a code the
        // frontend recognizes. No network call happens.
        let error = wordmark_rewrite(WordmarkRewriteRequest {
            text: "some text to rewrite".to_string(),
            base_url: "https://api.example.com".to_string(),
            model: "m".to_string(),
            disclaimer_acknowledged: false,
        })
        .expect_err("an online host requires the disclaimer");
        assert_eq!(error, "disclaimer_required");
    }

    #[test]
    fn wordmark_rewrite_rejects_empty_text() {
        assert!(wordmark_rewrite(WordmarkRewriteRequest {
            text: String::new(),
            base_url: "http://localhost:11434".to_string(),
            model: "m".to_string(),
            disclaimer_acknowledged: false,
        })
        .is_err());
    }

    #[test]
    fn binoculars_availability_matches_the_build() {
        // The availability flag tracks the feature, and without it the load
        // command refuses by name rather than pretending to have a model.
        #[cfg(not(feature = "embedded-llama"))]
        {
            assert!(!wordmark_binoculars_available());
            let error = wordmark_binoculars_load(BinocularsLoadRequest {
                observer_path: "a.gguf".to_string(),
                performer_path: "b.gguf".to_string(),
            })
            .expect_err("no embedded model in the default build");
            assert!(error.contains("not available"));
        }
        #[cfg(feature = "embedded-llama")]
        {
            assert!(wordmark_binoculars_available());
        }
    }

    /// Live Binoculars through the Tauri commands with two real models. Ignored
    /// by default: set STEGANO_WM_TEST_MODEL and STEGANO_WM_TEST_MODEL2 and run
    /// with `--features embedded-llama -- --ignored`.
    #[cfg(feature = "embedded-llama")]
    #[test]
    #[ignore = "needs two real GGUFs (STEGANO_WM_TEST_MODEL, STEGANO_WM_TEST_MODEL2)"]
    fn binoculars_live_scores_with_two_models() {
        let observer_path = std::env::var("STEGANO_WM_TEST_MODEL").unwrap();
        let performer_path = std::env::var("STEGANO_WM_TEST_MODEL2").unwrap();
        wordmark_binoculars_load(BinocularsLoadRequest {
            observer_path,
            performer_path,
        })
        .expect("both models load");
        let response = wordmark_binoculars_analyze(BinocularsAnalyzeRequest {
            text: "The quick brown fox jumps over the lazy dog and then runs away.".to_string(),
        })
        .expect("the loaded models score the text");
        assert!(
            response.score.is_finite() && response.score > 0.0,
            "score {} is finite and positive",
            response.score
        );
    }

    #[test]
    fn ai_regulation_c2pa_reports_absent_on_a_plain_image() {
        let bytes =
            include_bytes!("../../stegano-core/tests/fixtures/c2pa/no_manifest.png").to_vec();
        let report = c2pa_inspect(C2paInspectRequest {
            bytes,
            format_hint: Some("no_manifest.png".to_string()),
        })
        .expect("a plain image reads as absent, not an error");
        assert!(!report.present, "a file with no credential is absent");
        assert_eq!(
            report.verdict,
            stegano_core::c2pa_read::C2paVerdict::Absent,
            "the verdict is exactly what the reader returned"
        );
    }

    #[test]
    fn ai_regulation_c2pa_names_empty_bytes() {
        let error = c2pa_inspect(C2paInspectRequest {
            bytes: Vec::new(),
            format_hint: None,
        })
        .expect_err("empty bytes must be refused by name");
        assert!(!error.is_empty(), "the refusal says something");
    }

    // ─── Files ──────────────────────────────────────────────────

    /// A cover long enough for the zero-width carrier to place a byte of payload,
    /// matching the file layer's own fixture cover.
    const FILES_COVER: &str = "The quick brown fox jumps over the lazy dog near the bank";

    /// Mark `FILES_COVER` with a real zero-width payload, so the fixture provably
    /// carries a mark the core's own carrier placed.
    fn files_zero_width_marked() -> String {
        use stegano_core::stego::ZeroWidth;
        let marked = ZeroWidth::new().encode(FILES_COVER, b"x").unwrap();
        assert_ne!(marked, FILES_COVER, "the fixture must carry a real mark");
        marked
    }

    /// A minimal single-part DOCX whose body paragraph carries the zero-width
    /// mark, built the same way the file layer's own tests build their fixtures:
    /// a stored (uncompressed) ZIP needing no compression codec.
    fn files_marked_docx() -> Vec<u8> {
        use std::io::{Cursor, Write};
        let marked = files_zero_width_marked();
        let doc_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n\
  <w:body>\n\
    <w:p><w:r><w:t xml:space=\"preserve\">{marked}</w:t></w:r></w:p>\n\
  </w:body>\n\
</w:document>"
        );
        let entries = [
            ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>".to_string()),
            ("word/document.xml", doc_xml),
        ];
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, content) in &entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(content.as_bytes()).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn file_inspect_reports_a_planted_mark_in_a_marked_document() {
        let marked = files_zero_width_marked();
        let report = file_inspect(FileInspectRequest {
            bytes: marked.into_bytes(),
            format: "md".to_string(),
        })
        .expect("a marked markdown file inspects");
        let finding = report
            .classes
            .iter()
            .find(|c| c.id == "zero_width")
            .expect("the zero-width class is always listed");
        assert!(finding.count > 0, "the planted mark is seen");
    }

    /// A minimal PNG carrying a metadata (tEXt) chunk alongside the pixel data.
    fn files_png_with_metadata() -> Vec<u8> {
        fn chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
            let mut c = Vec::new();
            c.extend_from_slice(&(data.len() as u32).to_be_bytes());
            c.extend_from_slice(ctype);
            c.extend_from_slice(data);
            c.extend_from_slice(&[0, 0, 0, 0]);
            c
        }
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        png.extend_from_slice(&chunk(b"tEXt", b"steganohero\0payload"));
        png.extend_from_slice(&chunk(b"IDAT", &[7, 7, 7, 7, 1, 2, 3, 4]));
        png.extend_from_slice(&chunk(b"IEND", &[]));
        png
    }

    #[test]
    fn file_strip_removes_metadata_and_keeps_content() {
        let response = file_strip(FileStripRequest {
            bytes: files_png_with_metadata(),
            format: "png".to_string(),
        })
        .expect("a PNG with metadata strips");
        assert!(response.altered, "metadata was present, so the bytes change");
        assert!(response.content_identical, "a strip never touches the content");
        assert!(
            !response.bytes.windows(4).any(|w| w == b"tEXt"),
            "the metadata chunk is removed from the returned file"
        );
    }

    #[test]
    fn file_strip_on_a_text_file_is_refused_by_name() {
        let error = file_strip(FileStripRequest {
            bytes: b"# just text\n".to_vec(),
            format: "md".to_string(),
        })
        .expect_err("a text file has no metadata to strip");
        assert!(!error.is_empty(), "the refusal is named: {error}");
    }

    #[test]
    fn file_pristine_removes_marks_and_invisibles_and_names_the_trade_off() {
        // A real zero-width mark plus orphan invisibles no mark class owns.
        let dirty = format!("{}\u{00AD}\u{2063}", files_zero_width_marked());
        let response = file_pristine(FilePristineRequest {
            bytes: dirty.into_bytes(),
            format: "txt".to_string(),
        })
        .expect("a marked, dirty text file cleans to pristine");
        assert!(response.altered, "the dirty text changed");
        assert!(response.invisibles_removed >= 1, "the orphan invisibles are counted");
        assert!(!response.notes.is_empty(), "the trade-off is named");
        let cleaned = response.cleaned_text.expect("text-native carries its cleaned text");
        assert!(
            !cleaned.chars().any(|c| c.is_control()
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2060}'..='\u{2064}' | '\u{00AD}')),
            "no invisible or format-control character remains: {cleaned:?}"
        );
    }

    #[test]
    fn file_pristine_on_a_container_is_refused_by_name() {
        let error = file_pristine(FilePristineRequest {
            bytes: files_marked_docx(),
            format: "docx".to_string(),
        })
        .expect_err("container pristine is refused");
        assert!(!error.is_empty(), "the refusal is named: {error}");
    }

    #[test]
    fn file_clean_strips_a_marked_text_file_and_returns_text_and_bytes() {
        let marked = files_zero_width_marked();
        let response = file_clean(FileCleanRequest {
            bytes: marked.into_bytes(),
            format: "txt".to_string(),
            classes: vec!["zero_width".to_string()],
        })
        .expect("a marked text file cleans");
        assert!(response.altered, "removing the planted class alters the file");
        // Text-native: the cleaned text is present and is the cover exactly.
        assert_eq!(
            response.cleaned_text.as_deref(),
            Some(FILES_COVER),
            "the cleaned text is returned for a text-native format"
        );
        // The cleaned bytes re-extract with no zero-width marks left.
        let recheck = file_inspect(FileInspectRequest {
            bytes: response.bytes.clone(),
            format: "txt".to_string(),
        })
        .expect("the cleaned bytes inspect");
        assert_eq!(
            recheck
                .classes
                .iter()
                .find(|c| c.id == "zero_width")
                .unwrap()
                .count,
            0,
            "the written-back file carries no zero-width marks"
        );
        assert!(
            response.removed.iter().any(|r| r.id == "zero_width" && r.count > 0),
            "the removed count is reported for the chosen class"
        );
        assert!(!response.residual.is_empty(), "the honest residual note is present");
    }

    #[test]
    fn file_clean_strips_an_invisible_class_from_a_docx_and_reports_the_count() {
        let bytes = files_marked_docx();
        let response = file_clean(FileCleanRequest {
            bytes,
            format: "docx".to_string(),
            classes: vec!["zero_width".to_string()],
        })
        .expect("a marked DOCX cleans its invisible class");
        assert!(response.altered, "the container write-back changed the bytes");
        assert!(
            response.removed.iter().any(|r| r.id == "zero_width" && r.count > 0),
            "the removed count is reported for the chosen class"
        );
        // A container is not text-native: no fabricated text preview (invariant 2).
        assert!(
            response.cleaned_text.is_none(),
            "a container clean returns no text preview"
        );
        assert_eq!(response.format, "docx", "the format is echoed back");
        // The written-back archive re-extracts with the mark gone.
        let recheck = file_inspect(FileInspectRequest {
            bytes: response.bytes,
            format: "docx".to_string(),
        })
        .expect("the cleaned DOCX inspects");
        assert_eq!(
            recheck
                .classes
                .iter()
                .find(|c| c.id == "zero_width")
                .unwrap()
                .count,
            0,
            "the cleaned DOCX carries no zero-width marks"
        );
    }

    #[test]
    fn file_inspect_refuses_an_unknown_format_by_name() {
        let error = file_inspect(FileInspectRequest {
            bytes: b"not a real document".to_vec(),
            format: "pdf".to_string(),
        })
        .expect_err("an unsupported format must be refused");
        assert!(error.contains("pdf"), "the refusal names the format: {error}");
    }

    #[test]
    fn file_clean_refuses_a_container_homoglyph_by_name() {
        // Reverting look-alike substitutions in a container is the (format, class)
        // combination the file layer cannot prove lossless, so it is refused by
        // name rather than approximated (invariant 2).
        let bytes = files_marked_docx();
        let error = file_clean(FileCleanRequest {
            bytes,
            format: "docx".to_string(),
            classes: vec!["homoglyph".to_string()],
        })
        .expect_err("a container homoglyph clean must be refused");
        assert!(error.contains("DOCX"), "the refusal names the format: {error}");
        assert!(
            error.to_lowercase().contains("look-alike"),
            "the refusal names the class: {error}"
        );
    }

    #[test]
    fn file_clean_refuses_an_unknown_class_by_name() {
        let marked = files_zero_width_marked();
        let error = file_clean(FileCleanRequest {
            bytes: marked.into_bytes(),
            format: "md".to_string(),
            classes: vec!["not_a_class".to_string()],
        })
        .expect_err("an unknown class id must be refused");
        assert!(
            error.contains("not_a_class"),
            "the refusal names the unknown class: {error}"
        );
    }

    #[test]
    fn file_analyze_reports_the_signature_of_a_marked_document() {
        // A markdown file whose text carries a real zero-width mark analyses to
        // the same Confirmed verdict and named signature that the text path
        // returns: file_analyze reads the file, then runs the very analysis
        // forensic_analyze runs, and hands back the identical report shape.
        let marked = files_zero_width_marked();
        let report = file_analyze(FileAnalyzeRequest {
            bytes: marked.into_bytes(),
            format: "md".to_string(),
        })
        .expect("a marked markdown file analyses");
        assert_eq!(report.verdict, forensic::Verdict::Confirmed);
        assert!(
            !report.stego_signatures.is_empty(),
            "the analysis reports the planted signature"
        );
    }

    #[test]
    fn file_analyze_refuses_an_unreadable_file_by_name() {
        // Bytes that are not a real DOCX cannot yield text; the file layer refuses
        // by name (naming the format) rather than analysing an empty document
        // (invariant 2), and file_analyze surfaces that named error unchanged.
        let error = file_analyze(FileAnalyzeRequest {
            bytes: b"not a real document".to_vec(),
            format: "docx".to_string(),
        })
        .expect_err("an unreadable document must be refused");
        assert!(
            error.contains("DOCX"),
            "the refusal names the format: {error}"
        );
    }

    #[test]
    fn file_analyze_refuses_an_unknown_format_by_name() {
        let error = file_analyze(FileAnalyzeRequest {
            bytes: b"anything".to_vec(),
            format: "pdf".to_string(),
        })
        .expect_err("an unsupported format must be refused");
        assert!(error.contains("pdf"), "the refusal names the format: {error}");
    }

    // ─── Payload shaping ────────────────────────────────────────

    #[test]
    fn a_file_payload_round_trips_through_attach_and_recover() {
        let data = b"the contents of a small file to hide".to_vec();
        let attached = attach_payload(String::new(), "notes.bin".to_string(), data.clone())
            .expect("a small file attaches");
        assert_eq!(attached.attached_bytes, data.len());
        assert!(attached.chars_after > attached.chars_before);

        let recovered = recover_attachments(attached.text).expect("the file lists back");
        assert!(recovered.present, "the text carries a file");
        assert_eq!(recovered.count, 1);
        assert_eq!(recovered.files[0].filename, "notes.bin");
        assert_eq!(
            recovered.files[0].data, data,
            "the recovered bytes are identical to the original"
        );
    }

    #[test]
    fn a_file_attaches_alongside_existing_text() {
        // "In addition to typed text": a file joins a message rather than
        // replacing it, and both come back.
        let attached = attach_payload(
            "a message that travels too".to_string(),
            "a.bin".to_string(),
            b"file bytes".to_vec(),
        )
        .expect("a file attaches to a non-empty text");
        assert!(attached.text.starts_with("a message that travels too"));
        let recovered = recover_attachments(attached.text).expect("recover");
        assert_eq!(recovered.count, 1);
        assert_eq!(recovered.files[0].data, b"file bytes");
    }

    #[test]
    fn an_empty_payload_file_is_refused_by_name() {
        let error = attach_payload("cover".to_string(), "empty.bin".to_string(), Vec::new())
            .expect_err("an empty file is not a payload");
        assert!(error.contains("empty"), "the refusal names the empty file: {error}");
    }

    #[test]
    fn an_over_large_payload_is_refused_by_name() {
        // The engine's own size ceiling: a file past it names its size rather
        // than being silently truncated.
        let big = vec![0u8; 100 * 1024 + 1];
        let error = attach_payload(String::new(), "big.bin".to_string(), big)
            .expect_err("a file past the engine limit is refused");
        assert!(
            error.contains("too large"),
            "the refusal names the size, not a truncation: {error}"
        );
    }

    #[test]
    fn a_payload_file_name_with_a_pipe_is_refused_by_name() {
        let error = attach_payload(String::new(), "a|b.bin".to_string(), b"data".to_vec())
            .expect_err("a name that would break the container is refused");
        assert!(error.contains('|'), "the refusal names the character: {error}");
    }

    #[test]
    fn recover_reports_absent_on_plain_text() {
        let recovered = recover_attachments("just some ordinary text".to_string())
            .expect("plain text recovers cleanly");
        assert!(!recovered.present);
        assert_eq!(recovered.count, 0);
    }

    #[test]
    fn compression_reduces_a_compressible_payload_and_expands_exactly() {
        let text = "repeat me. ".repeat(400);
        let data = text.as_bytes().to_vec();
        let compressed =
            compress_payload(data.clone(), None).expect("a compressible payload shrinks");
        assert_eq!(compressed.original_bytes, data.len());
        assert!(
            compressed.compressed_bytes < compressed.original_bytes,
            "a repetitive payload gets smaller: {} to {}",
            compressed.original_bytes,
            compressed.compressed_bytes
        );
        assert!(compressed.ratio < 1.0, "the measured ratio is below one");

        let expanded = expand_payload(compressed.compressed).expect("the payload restores");
        assert_eq!(
            expanded.byte_count,
            data.len(),
            "the restored size matches the original"
        );
        assert_eq!(
            expanded.plaintext.as_deref(),
            Some(text.as_str()),
            "the restored payload is byte for byte the original"
        );
    }

    #[test]
    fn compressing_then_attaching_then_expanding_recovers_the_original_file() {
        // The full payload-shaping path the interface offers: make a file
        // smaller, attach it to the layer, recover it, and restore it exactly.
        let original = "a file worth hiding, and worth compressing. ".repeat(64);
        let bytes = original.as_bytes().to_vec();
        let smaller = compress_payload(bytes.clone(), None).expect("compress");
        assert!(smaller.compressed_bytes < smaller.original_bytes);

        let attached =
            attach_payload(String::new(), "report.txt".to_string(), smaller.compressed.clone())
                .expect("attach the smaller payload");
        let recovered = recover_attachments(attached.text).expect("recover");
        assert_eq!(recovered.count, 1);
        assert_eq!(
            recovered.files[0].data, smaller.compressed,
            "the smaller bytes come back unchanged"
        );

        let restored = expand_payload(recovered.files[0].data.clone()).expect("restore");
        assert_eq!(restored.byte_count, bytes.len());
        assert_eq!(restored.plaintext.as_deref(), Some(original.as_str()));
    }

    #[test]
    fn an_empty_compression_input_is_refused_by_name() {
        let error = compress_payload(Vec::new(), None).expect_err("nothing to compress");
        assert!(error.contains("empty"), "the refusal names the empty payload: {error}");
    }

    #[test]
    fn an_over_range_compression_effort_is_refused_by_name() {
        let error =
            compress_payload(b"data".to_vec(), Some(10)).expect_err("the effort is bounded");
        assert!(
            error.contains("between 0 and 9"),
            "the refusal names the range: {error}"
        );
    }

    #[test]
    fn expanding_input_this_surface_did_not_produce_is_refused_by_name() {
        let error = expand_payload(b"this is not a restorable payload at all".to_vec())
            .expect_err("random bytes are not a restorable payload");
        assert!(!error.is_empty(), "the refusal says something: {error}");
    }

    // ─── Runtime configuration ──────────────────────────────────
    //
    // These exercise the exact dispatch the `settings_read` / `settings_update`
    // commands run, against a fresh in-memory store so they are deterministic
    // and independent of the process-wide store the commands use at runtime.

    fn fresh_store() -> SettingsStore {
        SettingsStore::in_memory(Settings::default())
    }

    #[test]
    fn settings_read_returns_the_current_configuration() {
        let mut store = fresh_store();
        let view = read_settings(&mut store).expect("reading the configuration succeeds");
        // The editable view and the accepted ranges both come back.
        assert_eq!(view["settings"]["density"]["mark"], serde_json::json!(0.85));
        assert_eq!(view["settings"]["crypto"]["memory_kib"], serde_json::json!(65536));
        assert_eq!(
            view["constraints"]["density"]["conceal"]["maximum"],
            serde_json::json!(0.60)
        );
        // The bearer token is never exposed through the read.
        assert!(view["settings"]["server"].get("bearer_token").is_none());
        assert_eq!(
            view["settings"]["server"]["bearer_token_present"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn a_valid_settings_update_is_stored_and_reads_back() {
        let mut store = fresh_store();
        let applied = apply_settings(
            &mut store,
            &serde_json::json!({
                "density": { "conceal": 0.40 },
                "crypto": { "time_cost": 5 }
            }),
        )
        .expect("a valid update is accepted");
        // The result reports what the core stored, not an optimistic echo.
        assert_eq!(applied["settings"]["density"]["conceal"], serde_json::json!(0.40));
        assert_eq!(applied["settings"]["crypto"]["time_cost"], serde_json::json!(5));

        // A fresh read of the same store returns the stored values.
        let read = read_settings(&mut store).expect("reading back succeeds");
        assert_eq!(read["settings"]["density"]["conceal"], serde_json::json!(0.40));
        assert_eq!(read["settings"]["crypto"]["time_cost"], serde_json::json!(5));
        // A field left out of the update is unchanged.
        assert_eq!(read["settings"]["density"]["mark"], serde_json::json!(0.85));
    }

    #[test]
    fn an_out_of_range_settings_value_is_refused_by_name_and_changes_nothing() {
        let mut store = fresh_store();
        // Mark's accepted range starts at 0.20; 0.01 is below it.
        let error = apply_settings(&mut store, &serde_json::json!({ "density": { "mark": 0.01 } }))
            .expect_err("an out-of-range value must be refused");
        assert!(
            error.contains("density.mark"),
            "the refusal names the offending field: {error}"
        );

        // Nothing changed: the stored value is still the default.
        let read = read_settings(&mut store).expect("reading back succeeds");
        assert_eq!(read["settings"]["density"]["mark"], serde_json::json!(0.85));
    }

    #[test]
    fn a_malformed_settings_value_is_refused_by_name_and_changes_nothing() {
        let mut store = fresh_store();
        // The memory cost is a whole number; a string is malformed.
        let error = apply_settings(
            &mut store,
            &serde_json::json!({ "crypto": { "memory_kib": "lots" } }),
        )
        .expect_err("a malformed value must be refused");
        assert!(
            error.contains("crypto.memory_kib"),
            "the refusal names the offending field: {error}"
        );

        let read = read_settings(&mut store).expect("reading back succeeds");
        assert_eq!(read["settings"]["crypto"]["memory_kib"], serde_json::json!(65536));
    }

    #[test]
    fn an_unknown_settings_field_is_refused_rather_than_ignored() {
        let mut store = fresh_store();
        let error = apply_settings(&mut store, &serde_json::json!({ "densty": { "mark": 0.5 } }))
            .expect_err("an unknown field must be refused");
        assert!(
            error.contains("densty"),
            "the refusal names the unknown field: {error}"
        );
    }
}
