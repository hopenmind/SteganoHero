//! Acceptance campaign contracts, driven over the real channel transport.
//!
//! Every assertion here goes through a JSON-RPC line exactly as an assisting
//! agent would send it, so what is proven is the surface as it is reached. The
//! file is split in two:
//!
//! - Guard tests hold properties that are true today and must stay true when
//!   the pipeline, license and capacity work in flight lands. They are the
//!   anti-regression net for the invariants an agent depends on.
//! - Contract tests, marked `#[ignore]`, hold properties that are NOT true
//!   today. Each names the defect it waits on. They are written as the correct
//!   behaviour, never as a pin on the current one, so the day the defect is
//!   fixed the test is un-ignored and passes unchanged. Leaving them ignored
//!   keeps the suite green without pretending the defect is acceptable.
//!
//! These sit alongside `corpus.rs`; they do not replace it. Where they overlap
//! it is on purpose, because the property matters enough to be stated as a
//! contract in its own right.

use serde_json::{json, Value};

use stegano_mcp::channel::{self, Handled};
use stegano_mcp::settings::Settings;
use stegano_mcp::tools::SettingsStore;

// ─────────────────────────────────────────────────────────────
// Driving the surface over the channel
// ─────────────────────────────────────────────────────────────

struct Session {
    store: SettingsStore,
    next_id: u64,
}

impl Session {
    fn open() -> Self {
        let mut session = Self {
            store: SettingsStore::in_memory(Settings::default()),
            next_id: 1,
        };
        let ready = session.request("initialize", json!({ "protocolVersion": "2025-06-18" }));
        assert_eq!(ready["result"]["serverInfo"]["name"], json!("stegano-hero"));
        session.notify("notifications/initialized");
        session
    }

    fn handle(&mut self, method: &str, params: Value) -> Handled {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
            .to_string();
        channel::handle_line(&line, &mut self.store)
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let handled = self.handle(method, params);
        let response = handled
            .response
            .unwrap_or_else(|| panic!("{method} left the request unanswered"));
        serde_json::from_str(&response).expect("the answer must be JSON")
    }

    fn notify(&mut self, method: &str) {
        let line = json!({ "jsonrpc": "2.0", "method": method }).to_string();
        let handled = channel::handle_line(&line, &mut self.store);
        assert!(handled.response.is_none(), "{method} must not be answered");
    }

    /// The full response for a command call, along with the operator log line.
    fn call_raw(&mut self, name: &str, arguments: Value) -> (Value, String) {
        let line = json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        })
        .to_string();
        self.next_id += 1;
        let handled = channel::handle_line(&line, &mut self.store);
        let response: Value = serde_json::from_str(
            &handled.response.expect("a command call must be answered"),
        )
        .expect("the answer must be JSON");
        (response, handled.log)
    }

    fn run(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        assert!(
            response.get("error").is_none(),
            "{name} was refused at the protocol level: {}",
            response["error"]
        );
        assert_eq!(
            response["result"]["isError"],
            json!(false),
            "{name} refused: {}",
            response["result"]["structuredContent"]
        );
        response["result"]["structuredContent"].clone()
    }
}

// ─────────────────────────────────────────────────────────────
// The corpus
// ─────────────────────────────────────────────────────────────

fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("corpus")
}

fn document(name: &str) -> String {
    let path = corpus_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("corpus document {} is missing: {e}", path.display()))
}

const ALL_DOCUMENTS: [&str; 9] = [
    "en_long_article.txt",
    "fr_accented.txt",
    "technical_markdown.md",
    "mixed_multilingual.txt",
    "en_short.txt",
    "minimal_tiny.txt",
    "cjk_japanese.txt",
    "cyrillic_russian.txt",
    "already_carrying.txt",
];

const CARRIERS: [&str; 4] = ["zero_width", "whitespace_var", "bidi", "homoglyph"];

/// The mark identifying whichever secret or passcode a test placed. Its only
/// legitimate appearances are inside the arguments a caller supplied and inside
/// the result of a command explicitly asked to return it. It must never turn up
/// in a placement result, an analysis, a refusal reason or the operator log.
const SECRET: &str = "SECRET-DO-NOT-ECHO";
const PASSCODE: &str = "PASSCODE-DO-NOT-ECHO";

fn carrier_entry<'a>(report: &'a Value, carrier: &str) -> &'a Value {
    report["carriers"]
        .as_array()
        .expect("a report lists carriers")
        .iter()
        .find(|entry| entry["carrier"] == json!(carrier))
        .unwrap_or_else(|| panic!("{carrier} is missing from the report"))
}

fn is_error(response: &Value) -> bool {
    response["result"]["isError"] == json!(true)
}

fn refusal_code(response: &Value) -> String {
    response["result"]["structuredContent"]["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

// ═════════════════════════════════════════════════════════════
// Guard tests: true today, must stay true through the fixes in flight
// ═════════════════════════════════════════════════════════════

/// Invariant 2, stated as a contract over the whole corpus. Placing a secret
/// either succeeds with a confirmed round trip, or refuses by name. It is never
/// a success carrying a round trip it could not confirm. This is the property
/// that hid a plaintext leak in the earlier version, so it is checked on every
/// carrier against every document rather than sampled.
#[test]
fn conceal_is_a_confirmed_success_or_a_named_refusal_never_a_quiet_half_result() {
    let mut session = Session::open();
    for name in ALL_DOCUMENTS {
        let cover = document(name);
        for carrier in CARRIERS {
            let (response, _log) = session.call_raw(
                "conceal",
                json!({ "cover": cover, "secret": SECRET, "carriers": [carrier] }),
            );

            // A usable placement path never surfaces as a protocol error: the
            // arguments are valid, so the answer is a result, refusal included.
            assert!(
                response.get("error").is_none(),
                "{name} with {carrier}: a valid conceal call came back as a protocol error: {}",
                response["error"]
            );

            if is_error(&response) {
                let code = refusal_code(&response);
                assert!(
                    code == "placement_refused" || code == "round_trip_unverified",
                    "{name} with {carrier}: refused with '{code}', which names neither room nor read-back"
                );
            } else {
                let structured = &response["result"]["structuredContent"];
                assert_eq!(
                    structured["round_trip"]["verified"],
                    json!(true),
                    "{name} with {carrier}: conceal returned a success whose round trip it did not confirm. \
                     By default that must be a refusal, not a result."
                );
            }
        }
    }
}

/// No secret and no passcode may appear in a placement result, in an inspection
/// of the placed text, or in the operator log line for the call. The only place
/// the secret is allowed to reappear is a command explicitly asked to return
/// it, which conceal and inspect are not.
#[test]
fn a_placed_secret_and_its_passcode_stay_out_of_results_and_the_log() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");

    let (placed, log) = session.call_raw(
        "conceal",
        json!({
            "cover": cover,
            "secret": SECRET,
            "carriers": ["zero_width"],
            "cipher": "aes256_gcm",
            "passcode": PASSCODE,
        }),
    );
    assert!(!is_error(&placed), "the placement must succeed on the long article");
    let placed_text = placed.to_string();
    assert!(!placed_text.contains(SECRET), "the secret appeared in the placement result");
    assert!(!placed_text.contains(PASSCODE), "the passcode appeared in the placement result");
    assert_eq!(log, "tools/call: answered");
    assert!(!log.contains(SECRET) && !log.contains(PASSCODE));

    let stego = placed["result"]["structuredContent"]["stego_text"].clone();

    // Inspecting the prepared text reports its shape without opening it.
    let seen = session.run("inspect", json!({ "text": stego }));
    let seen_text = seen.to_string();
    assert!(!seen_text.contains(SECRET), "inspect exposed the secret");
    assert!(!seen_text.contains(PASSCODE), "inspect exposed the passcode");

    // A full analysis likewise says nothing of the content it cannot open.
    let analysed = session.run("analyze", json!({ "text": stego }));
    let analysed_text = analysed.to_string();
    assert!(!analysed_text.contains(SECRET), "analyze exposed the secret");
    assert!(!analysed_text.contains(PASSCODE), "analyze exposed the passcode");
}

/// A confidentiality layer opened with the wrong passcode is a refusal that
/// names itself, never a success carrying unverified bytes, and the refusal
/// reason carries neither the secret nor the passcode that was tried.
#[test]
fn a_wrong_passcode_is_a_named_refusal_that_leaks_nothing() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");
    let placed = session.run(
        "conceal",
        json!({
            "cover": cover,
            "secret": SECRET,
            "carriers": ["zero_width"],
            "cipher": "chacha20_poly1305",
            "passcode": PASSCODE,
        }),
    );

    let (response, _log) = session.call_raw(
        "reveal",
        json!({
            "text": placed["stego_text"],
            "carriers": ["zero_width"],
            "passcode": "the-wrong-passcode",
        }),
    );
    assert!(is_error(&response), "a wrong passcode must be refused, not answered");
    assert_eq!(refusal_code(&response), "recovery_refused");
    let reason = response["result"]["structuredContent"]["error"]["reason"]
        .as_str()
        .unwrap_or("");
    assert!(!reason.contains(SECRET), "the refusal reason exposed the secret");
    assert!(!reason.contains(PASSCODE), "the refusal reason exposed the passcode");
}

/// A carrier that has no room in a given script reports zero, explains why in
/// terms of the script, and does so inside a report that at the same time shows
/// a different carrier the document can still use. Zero capacity on one carrier
/// is only actionable if the alternative is visible in the same answer.
#[test]
fn a_script_that_defeats_one_carrier_still_names_a_usable_one_in_the_same_report() {
    let mut session = Session::open();
    for name in ["cjk_japanese.txt", "cyrillic_russian.txt"] {
        let report = session.run("capacity_report", json!({ "cover": document(name) }));

        let blocked = carrier_entry(&report, "homoglyph");
        assert_eq!(blocked["positions"], json!(0), "{name}: homoglyph should have no room here");
        let reason = blocked["zero_reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("script"),
            "{name}: the zero must be explained by the script, reason was: {reason}"
        );

        // The same report must expose at least one carrier the document can
        // still use, so the caller reads the alternative off the answer that
        // refused the first. A carrier with real room, or one the cover does not
        // bound (which stays usable by extending the document), is such an
        // alternative.
        let alternative = ["zero_width", "whitespace_var", "bidi"].iter().find(|other| {
            let entry = carrier_entry(&report, other);
            entry["secret_bytes"].as_u64().unwrap_or(0) > 0
                || entry["cover_bounds_writes"] == json!(false)
        });
        assert!(
            alternative.is_some(),
            "{name}: homoglyph has no room and the report names no carrier that does"
        );
    }
}

/// A capacity report that offers a shortfall gives the arithmetic, not just a
/// verdict. The smallest document is short of a single byte through the visible
/// carrier, and the report must say by how much.
#[test]
fn a_capacity_shortfall_is_reported_with_its_arithmetic() {
    let mut session = Session::open();
    let report = session.run("capacity_report", json!({ "cover": document("minimal_tiny.txt") }));
    let blocked = carrier_entry(&report, "homoglyph");
    assert_eq!(blocked["secret_bytes"], json!(0));
    let reason = blocked["zero_reason"].as_str().unwrap_or("");
    assert!(reason.contains("3 positions"), "the shortfall must state the positions, reason was: {reason}");
    assert!(reason.contains("8"), "the shortfall must state the byte threshold, reason was: {reason}");
}

/// The catalogue an agent reads, over the live channel, carries none of the
/// punctuation the writing rules reject. This extends the static check in the
/// library to the payload as it is actually rendered and sent.
#[test]
fn the_advertised_catalogue_over_the_channel_is_free_of_the_rejected_marks() {
    let mut session = Session::open();
    let listed = session.request("tools/list", json!({}));
    let capabilities = session.run("capabilities_list", json!({}));

    for payload in [listed.to_string(), capabilities.to_string()] {
        assert!(!payload.contains('\u{2014}'), "an em dash reached the advertised catalogue");
        assert!(!payload.contains('\u{2013}'), "an en dash reached the advertised catalogue");
        assert!(!payload.contains('\u{2026}'), "an ellipsis character reached the advertised catalogue");
    }
}

/// F12, stated as the corrected contract. An authorship claim covers the
/// document it is attached to, so editing the visible writing after the claim
/// is attached invalidates it, and verification refuses by name rather than
/// confirming a document that changed under the claim. The earlier version
/// signed only the claim; the corpus test `a_claim_states_that_it_covers_
/// itself_and_not_the_text_around_it` still encodes that older behaviour and
/// fails now that the fix has landed. This guard holds the fixed behaviour, so
/// it protects the correction rather than the defect it replaced.
#[test]
fn an_authorship_claim_is_invalidated_when_the_visible_text_is_edited() {
    let mut session = Session::open();
    let keys = session.run("authorship_keypair", json!({}));
    let signed = session.run(
        "authorship_sign",
        json!({
            "cover": document("en_long_article.txt"),
            "author": "Hope 'n Mind",
            "private_key_base64": keys["private_key_base64"],
        }),
    );

    // Unedited, the claim verifies.
    let checked = session.run(
        "authorship_verify",
        json!({
            "text": signed["signed_text"],
            "public_key_base64": keys["public_key_base64"],
        }),
    );
    assert_eq!(checked["verified"], json!(true));

    // Edited, verification refuses rather than confirming a changed document.
    let edited = format!(
        "{} One more sentence, added by somebody else.",
        signed["signed_text"].as_str().unwrap()
    );
    let (response, _) = session.call_raw(
        "authorship_verify",
        json!({
            "text": edited,
            "public_key_base64": keys["public_key_base64"],
        }),
    );
    assert!(
        is_error(&response),
        "editing the visible writing must invalidate the claim, not leave it confirmed"
    );
    assert_eq!(refusal_code(&response), "verification_refused");
    let reason = response["result"]["structuredContent"]["error"]["reason"]
        .as_str()
        .unwrap_or("");
    assert!(
        reason.contains("hash mismatch") || reason.contains("altered"),
        "the refusal must name the alteration, reason was: {reason}"
    );
}

// ═════════════════════════════════════════════════════════════
// Contract tests: NOT true today. Ignored, each naming its defect.
// Un-ignore and re-run when the named fix lands.
// ═════════════════════════════════════════════════════════════

/// NEW FINDING (high). On legitimate monolingual Russian, `analyze` returns
/// verdict "Confirmed" and a homoglyph signature with `decodable: true` and an
/// estimated payload size, i.e. it claims to have found and decoded a hidden
/// payload in ordinary text. At the same time `capacity_report` reports zero
/// homoglyph room, `mark_batch` refuses for want of substitutable characters,
/// and `sanitize` refuses with `no_marking_found`. Four commands, and only one
/// of them says the document is carrying anything. The claim is the wrong one.
///
/// Root: `forensic.rs` builds each signature's `decodable` flag from
/// `carrier.decode(text).is_ok()`, and a carrier's decode returns Ok on any
/// text that merely contains its alphabet, so the flag fires on unmarked text.
/// `score_to_verdict` then escalates any decodable signature to Confirmed.
///
/// The contract: a document that every capability command agrees is unmarked
/// must not be reported by `analyze` as carrying a decodable payload.
///
/// Ignored because it fails today. `metrics.rs` and the forensic path are under
/// concurrent change; un-ignore and re-run once that work lands.
#[test]
#[ignore = "new finding: analyze confirms a decodable payload in unmarked monolingual Russian; see forensic.rs decodable flag"]
fn analyze_does_not_confirm_a_decodable_payload_in_a_document_every_other_command_calls_unmarked() {
    let mut session = Session::open();
    let russian = document("cyrillic_russian.txt");

    // The capability commands agree the document is unmarked.
    let capacity = session.run("capacity_report", json!({ "cover": russian }));
    assert_eq!(carrier_entry(&capacity, "homoglyph")["positions"], json!(0));

    let (mark, _) = session.call_raw(
        "mark_batch",
        json!({ "text": russian, "recipients": ["only-one"], "salt": "s" }),
    );
    assert!(is_error(&mark), "mark_batch should find nothing to mark here");

    let (clean, _) = session.call_raw(
        "sanitize",
        json!({ "text": russian, "channels": ["homoglyph"], "allow_visible_text_rewrite": true }),
    );
    assert_eq!(refusal_code(&clean), "no_marking_found");

    // Therefore analyze must not claim a decodable payload, nor a Confirmed
    // verdict driven by one.
    let report = session.run("analyze", json!({ "text": russian }));
    assert_ne!(
        report["verdict"], json!("Confirmed"),
        "analyze confirmed a payload in a document every other command calls unmarked"
    );
    for signature in report["stego_signatures"].as_array().unwrap_or(&vec![]) {
        assert_ne!(
            signature["decodable"], json!(true),
            "analyze reported a decodable signature on unmarked text: {signature}"
        );
    }
}

/// FIXED. The signature detail strings `analyze` returns once carried a real em
/// dash, for example "detected with 100% confidence \u{2014} payload is
/// decodable" (forensic.rs, the three detail formats). Tool output is the most
/// externally visible text the project produces, and the writing rules reject
/// em dashes in anything user facing. The static catalogue was clean; this is
/// the runtime analysis output, which the catalogue check never reaches, so the
/// finding needed a check of its own.
///
/// The contract: no user-facing string an agent receives from `analyze` carries
/// an em dash. Driven on the document that made the detector emit one.
///
/// The detail strings have since been rewritten with plain punctuation, so this
/// runs rather than standing aside. It stays as the guard against the mark
/// coming back through a path the catalogue check cannot see.
#[test]
fn analyze_runtime_output_carries_no_em_dash() {
    let mut session = Session::open();
    let report = session.run("analyze", json!({ "text": document("cyrillic_russian.txt") }));
    assert!(
        !report.to_string().contains('\u{2014}'),
        "an em dash reached the user-facing analysis output"
    );
}

/// NEW FINDING (low). `mark_batch` reports `max_recipients` as a raw saturated
/// integer. A document with 64 or more substitutable positions reports
/// 18446744073709551615, the u64 ceiling, because the true figure is 2 to the
/// power of the mark width and overflows. Presented plainly as "how many
/// recipients the document can support", that number is an artefact of
/// saturation, not a bound anyone can act on.
///
/// The contract: when the ceiling is the saturated maximum, the answer says so,
/// rather than handing back the raw ceiling as if it were a measured figure.
///
/// Ignored because it fails today. Un-ignore when the saturated case is either
/// bounded to a meaningful figure or annotated as saturated.
#[test]
#[ignore = "new finding: mark_batch reports a saturated u64 ceiling as max_recipients with no note; low severity"]
fn mark_batch_does_not_hand_back_a_saturated_ceiling_unannotated() {
    let mut session = Session::open();
    let batch = session.run(
        "mark_batch",
        json!({
            "text": document("en_long_article.txt"),
            "recipients": ["a", "b"],
            "salt": "s",
        }),
    );
    let ceiling = batch["max_recipients"].as_u64().unwrap();
    if ceiling == u64::MAX {
        let annotated = batch
            .as_object()
            .unwrap()
            .values()
            .filter_map(|value| value.as_str())
            .any(|text| {
                let lower = text.to_lowercase();
                lower.contains("saturat")
                    || lower.contains("at least")
                    || lower.contains("more than")
                    || lower.contains("exceeds")
            });
        assert!(
            annotated,
            "max_recipients saturated to the u64 ceiling but nothing in the answer says so"
        );
    }
}
