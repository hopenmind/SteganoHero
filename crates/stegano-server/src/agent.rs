//! The agent-facing REST surface and the configuration zone.
//!
//! Every route here dispatches through `stegano_mcp::tools::call`, the same
//! function the channel transport calls. The two therefore answer identically
//! because they run the same code, not because two implementations are kept in
//! step by hand.
//!
//! The command routes are reached at `/api/v1/tools/{name}`, one path per
//! command, with the command's arguments as the request body. The list at
//! `/api/v1/tools` is the same catalogue the channel advertises.
//!
//! Everything on this surface is behind the bearer token. There is no free
//! route here: the surface either has a token or does not start.

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use stegano_mcp::settings::Settings;
use stegano_mcp::tools::{self, Outcome, SettingsStore};

use crate::config;

/// State shared by every route on this surface.
pub struct AgentState {
    store: Mutex<SettingsStore>,
}

impl AgentState {
    pub fn new(store: SettingsStore) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }

    fn token(&self) -> String {
        self.store
            .lock()
            .expect("the settings lock is never held across a failure")
            .settings()
            .server
            .bearer_token
            .clone()
    }
}

/// Build the routes. The command paths come from the command catalogue, so a
/// command added to the catalogue is reachable here without another edit.
pub fn routes(state: Arc<AgentState>) -> Router {
    Router::new()
        .route("/api/v1/tools", get(list_tools))
        .route("/api/v1/tools/{name}", post(call_tool))
        .route("/api/v1/config", get(read_config).put(update_config))
        .route("/api/v1/config/constraints", get(read_constraints))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            bearer_middleware,
        ))
        .with_state(state)
}

/// Require the bearer token on every route of this surface.
async fn bearer_middleware(
    State(state): State<Arc<AgentState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let configured = state.token();
    if configured.is_empty() {
        // Unreachable through the binary, which refuses to start without a
        // token. Refusing here as well means no configuration can ever make
        // this surface open.
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_token_configured",
            "this surface is not configured with a bearer token and will not answer",
        );
    }

    let presented = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");

    if !config::token_matches(presented, &configured) {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "bearer_token_required",
            "this surface requires a bearer token in the Authorization header",
        );
    }

    next.run(request).await
}

async fn list_tools() -> Json<Value> {
    Json(json!({
        "protocol_version": stegano_mcp::PROTOCOL_VERSION,
        "surface_version": stegano_mcp::SERVER_VERSION,
        "tools": tools::tool_list_payload(),
    }))
}

async fn call_tool(
    State(state): State<Arc<AgentState>>,
    Path(name): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let arguments = body.map(|Json(value)| value).unwrap_or(json!({}));
    let mut store = state
        .store
        .lock()
        .expect("the settings lock is never held across a failure");
    render_outcome(tools::call(&name, &arguments, &mut store))
}

async fn read_config(State(state): State<Arc<AgentState>>) -> Response {
    let mut store = state
        .store
        .lock()
        .expect("the settings lock is never held across a failure");
    render_outcome(tools::call("settings_read", &json!({}), &mut store))
}

async fn update_config(State(state): State<Arc<AgentState>>, body: Json<Value>) -> Response {
    let Json(update) = body;
    // The zone accepts either the settings object directly or the same shape
    // the command takes, so one caller does not have to know which transport
    // it is talking to.
    let arguments = match update.get("settings") {
        Some(_) => update,
        None => json!({ "settings": update }),
    };
    let mut store = state
        .store
        .lock()
        .expect("the settings lock is never held across a failure");
    render_outcome(tools::call("settings_update", &arguments, &mut store))
}

async fn read_constraints() -> Json<Value> {
    Json(Settings::constraints())
}

/// Map a command outcome onto a response.
///
/// A refusal is a refusal at the transport level too: it never arrives as a
/// success carrying an error field somewhere inside it.
fn render_outcome(outcome: Outcome) -> Response {
    match outcome {
        Outcome::Done(value) => (StatusCode::OK, Json(value)).into_response(),
        Outcome::Refused { code, reason } => {
            refusal(StatusCode::UNPROCESSABLE_ENTITY, code, &reason)
        }
        Outcome::BadArguments(reason) => {
            refusal(StatusCode::BAD_REQUEST, "bad_arguments", &reason)
        }
        Outcome::Unknown(reason) => refusal(StatusCode::NOT_FOUND, "unknown_command", &reason),
    }
}

fn refusal(status: StatusCode, code: &str, reason: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "reason": reason } })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    const TOKEN: &str = "shb_token_used_only_in_tests";

    fn app() -> Router {
        let mut settings = Settings::default();
        settings.server.bearer_token = TOKEN.into();
        routes(Arc::new(AgentState::new(SettingsStore::in_memory(settings))))
    }

    async fn send(request: Request<Body>) -> (StatusCode, Value) {
        let response = app().oneshot(request).await.expect("the router must answer");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .expect("the body must be readable");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("the body must be JSON")
        };
        (status, value)
    }

    fn authorised(method: &str, path: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("the request must build")
    }

    #[tokio::test]
    async fn every_route_refuses_without_the_token() {
        for (method, path) in [
            ("GET", "/api/v1/tools"),
            ("POST", "/api/v1/tools/analyze"),
            ("GET", "/api/v1/config"),
            ("PUT", "/api/v1/config"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("the request must build");
            let (status, body) = send(request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
            assert_eq!(body["error"]["code"], json!("bearer_token_required"));
        }
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/tools")
            .header("authorization", "Bearer shb_not_the_token")
            .body(Body::empty())
            .expect("the request must build");
        let (status, _) = send(request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// The REST listing and the channel catalogue are the same catalogue.
    #[tokio::test]
    async fn the_listed_commands_are_the_command_catalogue() {
        let (status, body) = send(authorised("GET", "/api/v1/tools", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<String> = body["tools"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(listed, tools::tool_names());
    }

    /// Every command in the catalogue is reachable at its own path. A command
    /// that could not be reached would break the promise that either transport
    /// gives the same answers.
    #[tokio::test]
    async fn every_command_is_reachable_at_its_own_path() {
        for name in tools::tool_names() {
            let (status, body) =
                send(authorised("POST", &format!("/api/v1/tools/{name}"), json!({}))).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{name} is in the catalogue but has no route"
            );
            if status == StatusCode::BAD_REQUEST {
                // Called with no arguments, so a command with required
                // arguments says which one is missing. That is a reachable
                // command answering, not a missing route.
                assert_eq!(body["error"]["code"], json!("bad_arguments"), "{name}");
            }
        }
    }

    #[tokio::test]
    async fn an_unknown_command_is_not_found() {
        let (status, body) =
            send(authorised("POST", "/api/v1/tools/not_a_command", json!({}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], json!("unknown_command"));
    }

    /// The same command, asked the same question over either transport, gives
    /// the same answer. It has to: both go through one dispatcher.
    ///
    /// The command compared here is one whose answer is fully determined by
    /// its input. Commands that report a measured average over an unordered
    /// collection can differ in the last bits of a floating-point figure
    /// between two runs, which is a property of the measurement and not of the
    /// transport, so comparing one of those would test the wrong thing.
    #[tokio::test]
    async fn a_command_answers_over_rest_exactly_as_it_does_over_the_channel() {
        let cover = "A plain sentence with nothing carried inside it at all, long enough to measure.";

        let (status, over_rest) = send(authorised(
            "POST",
            "/api/v1/tools/capacity_report",
            json!({ "cover": cover }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);

        let mut settings = Settings::default();
        settings.server.bearer_token = TOKEN.into();
        let mut store = SettingsStore::in_memory(settings);
        let over_channel =
            match tools::call("capacity_report", &json!({ "cover": cover }), &mut store) {
                Outcome::Done(value) => value,
                _ => panic!("the command must answer"),
            };

        assert_eq!(over_rest, over_channel);

        // And the shape of a report that does carry measured figures is the
        // same on both sides, verdict and counts included.
        let (_, analysed_over_rest) = send(authorised(
            "POST",
            "/api/v1/tools/analyze",
            json!({ "text": cover }),
        ))
        .await;
        let analysed_over_channel =
            match tools::call("analyze", &json!({ "text": cover }), &mut store) {
                Outcome::Done(value) => value,
                _ => panic!("the command must answer"),
            };
        assert_eq!(
            analysed_over_rest["verdict"],
            analysed_over_channel["verdict"]
        );
        assert_eq!(
            analysed_over_rest["unicode_analysis"],
            analysed_over_channel["unicode_analysis"]
        );
    }

    #[tokio::test]
    async fn a_refusal_arrives_as_a_refusal() {
        let (status, body) = send(authorised(
            "POST",
            "/api/v1/tools/sanitize",
            json!({ "text": "plain text", "channels": ["homoglyph"] }),
        ))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], json!("visible_rewrite_refused"));
    }

    #[tokio::test]
    async fn unusable_arguments_arrive_as_a_bad_request() {
        let (status, body) = send(authorised(
            "POST",
            "/api/v1/tools/conceal",
            json!({ "cover": "text", "secret": "x", "cipher": "aes256_gcm" }),
        ))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("passcode"));
    }

    #[tokio::test]
    async fn the_configuration_zone_reads_without_exposing_the_token() {
        let (status, body) = send(authorised("GET", "/api/v1/config", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["settings"]["language"], json!("en"));
        assert_eq!(body["settings"]["server"]["bearer_token_present"], json!(true));
        assert!(!body.to_string().contains(TOKEN));
    }

    #[tokio::test]
    async fn the_configuration_zone_accepts_a_valid_change() {
        let application = app();

        let updated = application
            .clone()
            .oneshot(authorised(
                "PUT",
                "/api/v1/config",
                json!({ "language": "fr", "density": { "conceal": 0.35 } }),
            ))
            .await
            .expect("must answer");
        assert_eq!(updated.status(), StatusCode::OK);

        // The same router instance holds the change.
        let read = application
            .oneshot(authorised("GET", "/api/v1/config", json!({})))
            .await
            .expect("must answer");
        let bytes = to_bytes(read.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["settings"]["language"], json!("fr"));
        assert_eq!(body["settings"]["density"]["conceal"], json!(0.35));
    }

    #[tokio::test]
    async fn the_configuration_zone_refuses_a_bad_value_and_changes_nothing() {
        let application = app();

        let refused = application
            .clone()
            .oneshot(authorised(
                "PUT",
                "/api/v1/config",
                json!({ "density": { "mark": 0.01 } }),
            ))
            .await
            .expect("must answer");
        assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = to_bytes(refused.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], json!("settings_rejected"));
        assert!(body["error"]["reason"].as_str().unwrap().contains("density.mark"));

        let read = application
            .oneshot(authorised("GET", "/api/v1/config", json!({})))
            .await
            .expect("must answer");
        let bytes = to_bytes(read.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["settings"]["density"]["mark"], json!(0.85));
    }

    #[tokio::test]
    async fn the_configuration_zone_refuses_to_change_the_token() {
        let (status, body) = send(authorised(
            "PUT",
            "/api/v1/config",
            json!({ "server": { "bearer_token": "shb_replacement" } }),
        ))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("server.bearer_token"));
    }

    #[tokio::test]
    async fn the_accepted_ranges_are_readable() {
        let (status, body) = send(authorised("GET", "/api/v1/config/constraints", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["density"]["conceal"]["maximum"], json!(0.60));
        assert_eq!(body["server"]["bearer_token"]["editable"], json!(false));
    }

    /// A full place-and-recover cycle over REST alone.
    #[tokio::test]
    async fn a_document_is_prepared_and_read_back_over_rest() {
        let cover = "Access to the open science project expectations are exceptional in scope and practice today across every possible aspect of ecosystem operations";

        let (status, placed) = send(authorised(
            "POST",
            "/api/v1/tools/conceal",
            json!({ "cover": cover, "secret": "over rest", "carriers": ["zero_width"] }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(placed["round_trip"]["verified"], json!(true));

        let (status, read) = send(authorised(
            "POST",
            "/api/v1/tools/reveal",
            json!({ "text": placed["stego_text"], "carriers": ["zero_width"] }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read["secret"]["text"], json!("over rest"));
    }

    /// The provenance commands are reachable over REST through the shared
    /// dispatch: sign a document, verify the record holds, tamper the document,
    /// and verify it fails by name. The keypair comes from the surface itself.
    #[tokio::test]
    async fn a_provenance_record_signs_verifies_and_names_a_tampered_document_over_rest() {
        let cover = "Access to the open science project expectations are exceptional in scope and practice today across every possible aspect of the ecosystem operations including all cooperative joint exercises previously associated with it.";

        let (status, keys) = send(authorised(
            "POST",
            "/api/v1/tools/authorship_keypair",
            json!({}),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, signed) = send(authorised(
            "POST",
            "/api/v1/tools/provenance_sign",
            json!({
                "cover": cover,
                "assertions": [{ "kind": "human_authorship", "author": "Hope 'n Mind" }],
                "private_key_base64": keys["private_key_base64"],
            }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(signed["binding"], json!("detached"));
        assert_eq!(signed["round_trip"]["verified"], json!(true));
        // The private key never travels back in the result.
        assert!(!signed
            .to_string()
            .contains(keys["private_key_base64"].as_str().unwrap()));

        let (status, verified) = send(authorised(
            "POST",
            "/api/v1/tools/provenance_verify",
            json!({
                "document": cover,
                "sidecar_base64": signed["sidecar"]["base64"],
                "trusted_keys_base64": [keys["public_key_base64"]],
            }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(verified["provenance_holds"], json!(true));

        let edited = format!("{cover} One more sentence, added later.");
        let (status, tampered) = send(authorised(
            "POST",
            "/api/v1/tools/provenance_verify",
            json!({
                "document": edited,
                "sidecar_base64": signed["sidecar"]["base64"],
                "trusted_keys_base64": [keys["public_key_base64"]],
            }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tampered["provenance_holds"], json!(false));
        assert_eq!(tampered["claims"][0]["document_unaltered"], json!(false));
        assert!(tampered["claims"][0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().contains("document altered")));
    }

    /// A document too small for an in-band record is refused with the named
    /// capacity arithmetic, arriving as a refusal at the transport level rather
    /// than a truncated success.
    #[tokio::test]
    async fn an_in_band_record_too_large_is_refused_over_rest() {
        let (_status, keys) = send(authorised(
            "POST",
            "/api/v1/tools/authorship_keypair",
            json!({}),
        ))
        .await;

        let (status, body) = send(authorised(
            "POST",
            "/api/v1/tools/provenance_sign",
            json!({
                "cover": "ok thanks",
                "assertions": [{ "kind": "human_authorship" }],
                "private_key_base64": keys["private_key_base64"],
                "binding": "in_band",
                "carrier": "homoglyph",
            }),
        ))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"]["code"], json!("capacity_exceeded"));
        assert!(body["error"]["reason"].as_str().unwrap().contains("bits"));
    }

    // ─────────────────────────────────────────────────────────
    // Document sovereignty (the AI-regulation tool) over REST
    // ─────────────────────────────────────────────────────────

    const NO_MANIFEST_PNG: &[u8] =
        include_bytes!("../../stegano-core/tests/fixtures/c2pa/no_manifest.png");

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

    /// The document-inspect and document-clean commands are reachable over REST
    /// through the shared dispatch: inspect reports the marks, clean removes a
    /// chosen class and leaves the rest, with the honest residual note.
    #[tokio::test]
    async fn document_inspect_and_clean_run_over_rest() {
        let original = corpus("already_carrying.txt");

        let (status, inspected) = send(authorised(
            "POST",
            "/api/v1/tools/document_inspect",
            json!({ "document": original }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        let zero_width = inspected["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!("zero_width"))
            .unwrap();
        assert_eq!(zero_width["count"], json!(2));

        let (status, cleaned) = send(authorised(
            "POST",
            "/api/v1/tools/document_clean",
            json!({ "document": original, "classes": ["zero_width"] }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cleaned["altered"], json!(true));
        assert_eq!(cleaned["removed"][0]["id"], json!("zero_width"));
        assert!(cleaned["residual"].as_array().unwrap().len() >= 3);
        let text = cleaned["cleaned_text"].as_str().unwrap();
        assert!(!text.contains('\u{200B}'));
        assert!(text.contains('\u{FEFF}'));
    }

    /// The C2PA reader is reachable over REST and reports a file with no
    /// credential as Absent, not as an error.
    #[tokio::test]
    async fn c2pa_inspect_reports_absent_over_rest() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let (status, report) = send(authorised(
            "POST",
            "/api/v1/tools/c2pa_inspect",
            json!({ "file_base64": B64.encode(NO_MANIFEST_PNG), "format_hint": "image/png" }),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["present"], json!(false));
        assert_eq!(report["verdict"], json!("absent"));
    }
}
