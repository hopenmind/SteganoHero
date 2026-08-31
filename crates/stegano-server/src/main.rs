mod agent;
mod auth;
mod config;

use std::sync::Arc;

use axum::{
    extract::Json,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use stegano_core::{
    crypto::ChaCha20,
    forensic, format, metrics, pipeline,
    stego::{Bidi, Homoglyph, WhitespaceVar, ZeroWidth},
    traits::{CryptoMethod, StegoMethod},
    watermark::fingerprint as canary,
};
use tracing_subscriber;

// ─── Request / Response types ───

#[derive(Deserialize)]
struct EncodeRequest {
    cover: String,
    secret: String,
    /// "zero_width" | "homoglyph"
    method: Option<String>,
    /// If true, encrypt with ChaCha20-Poly1305
    encrypt: Option<bool>,
    password: Option<String>,
}

#[derive(Serialize)]
struct EncodeResponse {
    stego_text: String,
    methods_used: Vec<String>,
    capacity_used_bits: usize,
    /// Framed bits the cover offered the narrowest carrier of the stack, not a
    /// sum over the carriers. Zero means the cover held no frame in its own
    /// positions, which a carrier that overflows can still place into. The
    /// `capacity` endpoint says which case it is, per carrier.
    capacity_available_bits: usize,
}

#[derive(Deserialize)]
struct DecodeRequest {
    text: String,
    method: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
struct DecodeResponse {
    hidden_text: String,
    methods_detected: Vec<String>,
    crypto_used: Option<String>,
    integrity_valid: bool,
}

#[derive(Deserialize)]
struct DetectRequest {
    text: String,
}

#[derive(Serialize)]
struct DetectResponse {
    methods: Vec<DetectedMethodResp>,
    overall_confidence: f64,
}

#[derive(Serialize)]
struct DetectedMethodResp {
    id: String,
    name: String,
    confidence: f64,
}

#[derive(Deserialize)]
struct MetricsRequest {
    original: String,
    stego: String,
}

#[derive(Serialize)]
struct MetricsResponse {
    shannon_delta: f64,
    noise_density: f64,
    perplexity_delta: f64,
    survival_score: f64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Helpers ───

fn get_method(name: &str) -> Result<Box<dyn StegoMethod>, String> {
    match name {
        "zero_width" | "zw" => Ok(Box::new(ZeroWidth::new())),
        "homoglyph" | "hg" => Ok(Box::new(Homoglyph::new())),
        "bidi" | "bidirectional" => Ok(Box::new(Bidi::new())),
        "whitespace_var" | "ws" => Ok(Box::new(WhitespaceVar::new())),
        other => Err(format!("unknown method: {other}")),
    }
}

// ─── Handlers ───

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

async fn handle_encode(
    Json(req): Json<EncodeRequest>,
) -> Result<Json<EncodeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let method_name = req.method.as_deref().unwrap_or("zero_width");
    let stego = get_method(method_name).map_err(|e| bad_request(&e))?;
    let chacha = ChaCha20::new();

    let crypto: Option<(&dyn CryptoMethod, &str)> = if req.encrypt.unwrap_or(false) {
        let pw = req
            .password
            .as_deref()
            .ok_or_else(|| bad_request("encrypt requires password"))?;
        Some((&chacha, pw))
    } else {
        None
    };

    let result = pipeline::encode(&req.cover, req.secret.as_bytes(), &[stego.as_ref()], crypto)
        .map_err(|e| bad_request(&e.to_string()))?;

    Ok(Json(EncodeResponse {
        stego_text: result.stego_text,
        methods_used: result.methods_used,
        capacity_used_bits: result.capacity_used_bits,
        capacity_available_bits: result.capacity_available_bits,
    }))
}

async fn handle_decode(
    Json(req): Json<DecodeRequest>,
) -> Result<Json<DecodeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let method_name = req.method.as_deref().unwrap_or("zero_width");
    let stego = get_method(method_name).map_err(|e| bad_request(&e))?;
    let chacha = ChaCha20::new();
    let cryptos: Vec<&dyn CryptoMethod> = vec![&chacha];

    let result = pipeline::decode(
        &req.text,
        &[stego.as_ref()],
        &cryptos,
        req.password.as_deref(),
    )
    .map_err(|e| bad_request(&e.to_string()))?;

    let hidden_text = String::from_utf8(result.hidden_data)
        .unwrap_or_else(|e| format!("[binary: {} bytes]", e.into_bytes().len()));

    Ok(Json(DecodeResponse {
        hidden_text,
        methods_detected: result.methods_detected,
        crypto_used: result.crypto_used,
        integrity_valid: result.integrity_valid,
    }))
}

async fn handle_detect(
    Json(req): Json<DetectRequest>,
) -> Json<DetectResponse> {
    let zw = ZeroWidth::new();
    let hg = Homoglyph::new();
    let bd = Bidi::new();
    let ws = WhitespaceVar::new();
    let methods: Vec<&dyn StegoMethod> = vec![&zw, &hg, &bd, &ws];

    let result = pipeline::detect(&req.text, &methods);

    Json(DetectResponse {
        methods: result
            .methods
            .into_iter()
            .map(|m| DetectedMethodResp {
                id: m.id,
                name: m.name,
                confidence: m.confidence,
            })
            .collect(),
        overall_confidence: result.overall_confidence,
    })
}

async fn handle_metrics(
    Json(req): Json<MetricsRequest>,
) -> Json<MetricsResponse> {
    let m = metrics::compute_metrics(&req.original, &req.stego);
    Json(MetricsResponse {
        shannon_delta: m.shannon_delta,
        noise_density: m.noise_density,
        perplexity_delta: m.perplexity_delta,
        survival_score: m.survival_score,
    })
}

// ─── Capacity ───

#[derive(Deserialize)]
struct CapacityRequest {
    cover: String,
    /// One carrier id, or omit to report every carrier.
    method: Option<String>,
}

#[derive(Serialize)]
struct CarrierCapacityReport {
    carrier: String,
    /// Substitutable positions the carrier can actually write into this cover.
    positions: usize,
    /// The largest secret the engine accepts here: ask for that many bytes and
    /// it takes them, one more is refused. Zero for a carrier the cover does not
    /// bound, whose reason says it places by extending the document instead.
    secret_bytes: usize,
    /// Payload bytes the framed document holds, before the envelope.
    framed_bytes: usize,
    /// Of `framed_bytes`, what the envelope and its integrity step take.
    overhead_bytes: usize,
    /// True when the cover bounds this carrier, so `secret_bytes` is a limit it
    /// holds itself to. False when it overflows past the cover by design.
    cover_bounds_writes: bool,
    /// Present only when `secret_bytes` is zero, naming why.
    zero_reason: Option<String>,
}

#[derive(Serialize)]
struct CapacityResponse {
    carriers: Vec<CarrierCapacityReport>,
    note: String,
}

/// Explain a zero, or `None` when the figure is not zero. Mirrors the reasons
/// the command surface gives, so both surfaces answer the same way.
fn capacity_zero_reason(
    positions: usize,
    cover_bounds_writes: bool,
    framed_bytes: usize,
    secret_bytes: usize,
) -> Option<String> {
    if secret_bytes > 0 {
        return None;
    }
    let reason = if !cover_bounds_writes {
        "the cover does not bound this carrier: it places by extending the document, so no fixed \
         limit applies here and secret_bytes is not a ceiling this carrier is held to."
            .to_string()
    } else if positions == 0 {
        "this cover offers no position this carrier can use. Availability depends on the script \
         and shape of the cover text."
            .to_string()
    } else if framed_bytes == 0 {
        if positions < 8 {
            format!(
                "this cover offers {positions} positions, fewer than the 8 needed to hold a single byte"
            )
        } else {
            format!(
                "this cover offers {positions} positions, fewer than a framed document needs, so it \
                 holds no frame at all"
            )
        }
    } else {
        format!(
            "this cover holds a {framed_bytes} byte frame, but the envelope and its integrity step \
             take all of it, so no secret fits"
        )
    };
    Some(reason)
}

/// The honest capacity of one carrier on one cover, every deduction named.
fn carrier_capacity_report(method: &dyn StegoMethod, cover: &str) -> CarrierCapacityReport {
    let positions = if method.check_writable(cover).is_ok() {
        method.positions(cover)
    } else {
        0
    };
    let bounded = format::cover_bounds_writes(method, cover);
    let single: [&dyn StegoMethod; 1] = [method];
    let (secret_bytes, framed_bytes, overhead_bytes) = match pipeline::capacity(cover, &single, None)
    {
        Ok(capacity) => {
            let carrier = &capacity.carriers[0];
            (
                carrier.secret_bytes,
                carrier.framed_bytes,
                carrier.overhead_bytes,
            )
        }
        Err(_) => (0, 0, 0),
    };
    CarrierCapacityReport {
        carrier: method.id().to_string(),
        positions,
        secret_bytes,
        framed_bytes,
        overhead_bytes,
        cover_bounds_writes: bounded,
        zero_reason: capacity_zero_reason(positions, bounded, framed_bytes, secret_bytes),
    }
}

/// The four carriers, in application order, for the whole-report path.
fn all_capacity_methods() -> Vec<Box<dyn StegoMethod>> {
    vec![
        Box::new(ZeroWidth::new()),
        Box::new(WhitespaceVar::new()),
        Box::new(Bidi::new()),
        Box::new(Homoglyph::new()),
    ]
}

async fn handle_capacity(
    Json(req): Json<CapacityRequest>,
) -> Result<Json<CapacityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let methods: Vec<Box<dyn StegoMethod>> = match req.method.as_deref() {
        Some(name) => vec![get_method(name).map_err(|e| bad_request(&e))?],
        None => all_capacity_methods(),
    };

    let carriers = methods
        .iter()
        .map(|method| carrier_capacity_report(method.as_ref(), &req.cover))
        .collect();

    Ok(Json(CapacityResponse {
        carriers,
        note: "secret_bytes is the largest secret each carrier accepts in this cover: ask for that \
               many bytes and the engine takes them, one more is refused with named arithmetic. \
               framed_bytes is what the framed document holds and overhead_bytes is what the \
               envelope and its integrity step take from it. A carrier the cover does not bound \
               reports zero and its reason says it places by extending the document."
            .to_string(),
    }))
}

// ─── Forensic handler ───

#[derive(Deserialize)]
struct ForensicRequest {
    text: String,
}

async fn handle_forensic(
    Json(req): Json<ForensicRequest>,
) -> Json<forensic::ForensicReport> {
    Json(forensic::analyze(&req.text))
}

// ─── Canary types ───

#[derive(Deserialize)]
struct CanaryGenerateRequest {
    text: String,
    recipients: Vec<String>,
    salt: String,
}

#[derive(Serialize)]
struct CanaryGenerateResponse {
    versions: Vec<CanaryVersionResp>,
    fingerprint_bits: usize,
    max_recipients: u64,
}

#[derive(Serialize)]
struct CanaryVersionResp {
    recipient_id: String,
    fingerprint_hash: String,
    text: String,
}

#[derive(Deserialize)]
struct CanaryIdentifyRequest {
    text: String,
    registry: Vec<canary::Recipient>,
}

#[derive(Serialize)]
struct CanaryIdentifyResponse {
    recipient_id: Option<String>,
    fingerprint_hash: Option<String>,
    confidence: f64,
}

// ─── Canary handlers ───

async fn handle_canary_generate(
    Json(req): Json<CanaryGenerateRequest>,
) -> Result<Json<CanaryGenerateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let refs: Vec<&str> = req.recipients.iter().map(|s| s.as_str()).collect();

    let batch = canary::generate_batch(&req.text, &refs, &req.salt)
        .map_err(|e| bad_request(&e.to_string()))?;

    Ok(Json(CanaryGenerateResponse {
        versions: batch
            .versions
            .into_iter()
            .map(|v| CanaryVersionResp {
                recipient_id: v.recipient.id,
                fingerprint_hash: v.recipient.fingerprint_hash,
                text: v.text,
            })
            .collect(),
        fingerprint_bits: batch.fingerprint_bits,
        max_recipients: batch.max_recipients,
    }))
}

async fn handle_canary_identify(
    Json(req): Json<CanaryIdentifyRequest>,
) -> Result<Json<CanaryIdentifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = canary::identify_leak(&req.text, &req.registry)
        .map_err(|e| bad_request(&e.to_string()))?;

    Ok(Json(CanaryIdentifyResponse {
        recipient_id: result.recipient.as_ref().map(|r| r.id.clone()),
        fingerprint_hash: result.recipient.as_ref().map(|r| r.fingerprint_hash.clone()),
        confidence: result.confidence,
    }))
}

fn bad_request(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

// ─── Main ───

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Resolve the configuration first. Without a bearer token, or with values
    // that do not pass their own checks, this surface does not start at all.
    let settings_path = std::env::var("STEGANO_SETTINGS")
        .unwrap_or_else(|_| "stegano-server.json".into());
    let startup = match config::prepare(std::path::Path::new(&settings_path)) {
        Ok(startup) => startup,
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(2);
        }
    };
    for warning in &startup.warnings {
        tracing::warn!("{warning}");
        eprintln!("{warning}");
    }
    if startup.token_generated {
        println!("=== BEARER TOKEN (save this, shown only once) ===");
        println!("  {}", startup.settings.server.bearer_token);
        println!("  written to {settings_path}");
        println!("=================================================");
    }
    let bind = startup.settings.server.bind_address.clone();
    let settings_store = match stegano_mcp::tools::SettingsStore::at(&settings_path) {
        Ok(store) => store,
        Err(reason) => {
            eprintln!("refusing to start: {reason}");
            std::process::exit(2);
        }
    };
    let agent_state = Arc::new(agent::AgentState::new(settings_store));

    // Initialize API key store
    let db_path = std::env::var("STEGANO_DB").unwrap_or_else(|_| "stegano.db".into());
    let key_store = auth::ApiKeyStore::open(&db_path).expect("Failed to open API key database");

    // Auto-create a bootstrap key if the database is fresh
    match key_store.list_keys() {
        Ok(keys) if keys.is_empty() => {
            let boot_key = key_store
                .create_key("bootstrap", "admin", 1000)
                .expect("Failed to create bootstrap key");
            println!("=== BOOTSTRAP API KEY (save this, shown only once) ===");
            println!("  {boot_key}");
            println!("======================================================");
        }
        _ => {}
    }

    let state = Arc::new(auth::AppState {
        key_store,
        rate_limiter: auth::RateLimiter::new(),
    });

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/encode", post(handle_encode))
        .route("/api/v1/decode", post(handle_decode))
        .route("/api/v1/capacity", post(handle_capacity))
        .route("/api/v1/detect", post(handle_detect))
        .route("/api/v1/metrics", post(handle_metrics))
        .route("/api/v1/forensic", post(handle_forensic))
        .route("/api/v1/canary", post(handle_canary_generate))
        .route("/api/v1/canary/identify", post(handle_canary_identify))
        .layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware))
        .with_state(state)
        .merge(agent::routes(agent_state));

    tracing::info!("SteganoHero server listening on {bind}");
    println!("SteganoHero server listening on http://{bind}");
    println!("Endpoints:");
    println!("  GET  /api/v1/health             (free)");
    println!("  POST /api/v1/forensic           (free)");
    println!("  POST /api/v1/encode             (API key)");
    println!("  POST /api/v1/decode             (API key)");
    println!("  POST /api/v1/capacity           (API key)");
    println!("  POST /api/v1/detect             (API key)");
    println!("  POST /api/v1/metrics            (API key)");
    println!("  POST /api/v1/canary             (API key)");
    println!("  POST /api/v1/canary/identify    (API key)");
    println!("  GET  /api/v1/tools              (bearer token)");
    println!(
        "  POST /api/v1/tools/{{name}}        (bearer token, {} commands)",
        stegano_mcp::tools::tool_names().len()
    );
    println!("  GET  /api/v1/config             (bearer token)");
    println!("  PUT  /api/v1/config             (bearer token)");
    println!("  GET  /api/v1/config/constraints (bearer token)");

    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// technical_markdown.md is the case that exposed the old lie: the
    /// substitution carrier once reported sixty bytes of room while the heavy
    /// frame accepted none. The endpoint reports the figure the engine honours,
    /// and under the light frame default (§3.2) this short cover now carries a
    /// real secret; a payload one byte past it is still refused by name.
    #[test]
    fn the_capacity_report_is_the_figure_the_engine_accepts() {
        let cover = corpus("technical_markdown.md");

        let homoglyph = carrier_capacity_report(&Homoglyph::new(), &cover);
        assert!(
            homoglyph.positions > 8,
            "this cover has plenty of raw positions for the substitution carrier"
        );
        assert!(
            homoglyph.secret_bytes > 0,
            "the light frame default makes this short cover usable, not the heavy zero"
        );

        for method in all_capacity_methods() {
            let report = carrier_capacity_report(method.as_ref(), &cover);
            if !report.cover_bounds_writes {
                continue;
            }
            if report.secret_bytes > 0 {
                assert!(
                    pipeline::encode(
                        &cover,
                        &vec![b'x'; report.secret_bytes],
                        &[method.as_ref()],
                        None
                    )
                    .is_ok(),
                    "{}: the reported {} bytes must be accepted",
                    report.carrier,
                    report.secret_bytes
                );
            }
            assert!(
                pipeline::encode(
                    &cover,
                    &vec![b'x'; report.secret_bytes + 1],
                    &[method.as_ref()],
                    None
                )
                .is_err(),
                "{}: one byte past secret_bytes must be refused",
                report.carrier
            );
        }
    }

    /// A document too small for any frame: every zero is explained, and every
    /// bounded carrier reporting zero really does refuse a one byte secret.
    #[test]
    fn every_zero_is_explained_and_the_refusal_is_real() {
        let cover = corpus("minimal_tiny.txt");
        for method in all_capacity_methods() {
            let report = carrier_capacity_report(method.as_ref(), &cover);
            if report.secret_bytes == 0 {
                assert!(
                    report.zero_reason.is_some(),
                    "{}: a zero needs a reason",
                    report.carrier
                );
            }
            if report.cover_bounds_writes && report.secret_bytes == 0 {
                assert!(
                    pipeline::encode(&cover, b"x", &[method.as_ref()], None).is_err(),
                    "{}: a bounded carrier reporting zero must refuse a one byte secret",
                    report.carrier
                );
            }
        }
    }
}
