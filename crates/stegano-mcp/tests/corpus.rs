//! The command surface, driven end to end over the reference corpus.
//!
//! Nothing here calls a handler directly. Every assertion goes through a
//! JSON-RPC line exactly as an assisting agent would send it, so what is
//! proven is the surface as it is reached, not the functions behind it.
//!
//! The corpus in `tests/corpus/` is nine documents chosen because each one
//! breaks something: a long article that works, a document too small to hold
//! anything, two written in scripts that leave one carrier with nothing to
//! work with, and one that was already carrying material before any of this
//! was applied. Their measured properties are recorded in `manifest.json` and
//! the expectations below are checked against it rather than restated.

use serde_json::{json, Value};

use stegano_mcp::channel;
use stegano_mcp::settings::Settings;
use stegano_mcp::tools::SettingsStore;

// ─────────────────────────────────────────────────────────────
// Driving the surface
// ─────────────────────────────────────────────────────────────

/// A session over the surface, holding its own settings.
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

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();
        let handled = channel::handle_line(&line, &mut self.store);
        let response = handled
            .response
            .unwrap_or_else(|| panic!("{method} left the request unanswered"));
        assert!(
            !response.contains('\n'),
            "{method} answered with more than one line"
        );
        serde_json::from_str(&response).expect("the answer must be JSON")
    }

    fn notify(&mut self, method: &str) {
        let line = json!({ "jsonrpc": "2.0", "method": method }).to_string();
        let handled = channel::handle_line(&line, &mut self.store);
        assert!(handled.response.is_none(), "{method} must not be answered");
    }

    /// Run a command and require it to succeed.
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

    /// Run a command and require it to refuse, returning the code and reason.
    fn refuse(&mut self, name: &str, arguments: Value) -> (String, String) {
        let response = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        assert!(
            response.get("error").is_none(),
            "{name} was expected to refuse with a reason, not with a protocol error: {}",
            response["error"]
        );
        assert_eq!(
            response["result"]["isError"],
            json!(true),
            "{name} was expected to refuse, it returned {}",
            response["result"]["structuredContent"]
        );
        let error = &response["result"]["structuredContent"]["error"];
        (
            error["code"].as_str().unwrap().to_string(),
            error["reason"].as_str().unwrap().to_string(),
        )
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

fn manifest() -> Value {
    let path = corpus_dir().join("manifest.json");
    serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the corpus manifest is missing: {e}")),
    )
    .expect("the corpus manifest must be JSON")
}

fn manifest_entry(name: &str) -> Value {
    manifest()["files"]
        .as_array()
        .expect("the manifest lists files")
        .iter()
        .find(|entry| entry["name"] == json!(name))
        .unwrap_or_else(|| panic!("{name} is not recorded in the manifest"))
        .clone()
}

fn carrier_report<'a>(report: &'a Value, carrier: &str) -> &'a Value {
    report["carriers"]
        .as_array()
        .expect("a report lists carriers")
        .iter()
        .find(|entry| entry["carrier"] == json!(carrier))
        .unwrap_or_else(|| panic!("{carrier} is missing from the report"))
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

// ─────────────────────────────────────────────────────────────
// Discovery
// ─────────────────────────────────────────────────────────────

#[test]
fn the_command_list_and_the_capability_list_agree() {
    let mut session = Session::open();
    let listed = session.request("tools/list", json!({}));
    let advertised: Vec<String> = listed["result"]["tools"]
        .as_array()
        .expect("an array of commands")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();

    let capabilities = session.run("capabilities_list", json!({}));
    let described: Vec<String> = capabilities["commands"]
        .as_array()
        .expect("an array of commands")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();

    assert_eq!(advertised, described);
    assert!(!advertised.is_empty());
}

/// Every carrier the surface advertises must be usable, and every carrier that
/// is usable must be advertised. This is what stops the catalogue drifting
/// away from the engine behind it.
#[test]
fn every_advertised_carrier_answers_a_capacity_question() {
    let mut session = Session::open();
    let capabilities = session.run("capabilities_list", json!({}));
    let advertised: Vec<String> = capabilities["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|carrier| carrier["id"].as_str().unwrap().to_string())
        .collect();

    let report = session.run(
        "capacity_report",
        json!({ "cover": document("en_long_article.txt") }),
    );
    let reported: Vec<String> = report["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|carrier| carrier["carrier"].as_str().unwrap().to_string())
        .collect();

    assert_eq!(advertised, reported);
}

// ─────────────────────────────────────────────────────────────
// Capacity across the corpus
// ─────────────────────────────────────────────────────────────

/// Capacity is reported per carrier for every document, and every zero is
/// explained. A zero with no explanation would leave a caller guessing whether
/// the document or the carrier was the problem.
#[test]
fn every_document_gets_a_capacity_answer_and_every_zero_is_explained() {
    let mut session = Session::open();
    for name in ALL_DOCUMENTS {
        let report = session.run("capacity_report", json!({ "cover": document(name) }));
        let carriers = report["carriers"].as_array().unwrap();
        assert_eq!(carriers.len(), 4, "{name}");

        for carrier in carriers {
            let bytes = carrier["secret_bytes"].as_u64().unwrap();
            let reason = &carrier["zero_reason"];
            if bytes == 0 {
                assert!(
                    reason.is_string() && !reason.as_str().unwrap().is_empty(),
                    "{name}: {} reports zero capacity with no reason",
                    carrier["carrier"]
                );
            } else {
                assert!(
                    reason.is_null(),
                    "{name}: {} reports capacity and a zero reason at once",
                    carrier["carrier"]
                );
            }
        }
    }
}

/// The reported position count is checked against the recorded corpus
/// measurements. It is the physical substitutable-position count the carrier
/// reads off the cover, so it must never exceed what the document offers, and a
/// document recorded as offering nothing must report nothing.
#[test]
fn measured_capacity_stays_within_the_recorded_corpus_measurements() {
    let mut session = Session::open();
    for name in ALL_DOCUMENTS {
        let recorded = manifest_entry(name)["homoglyph_positions"]
            .as_u64()
            .unwrap();
        let report = session.run("capacity_report", json!({ "cover": document(name) }));
        let measured = carrier_report(&report, "homoglyph")["positions"]
            .as_u64()
            .unwrap();

        assert!(
            measured <= recorded,
            "{name}: reports {measured} positions, the document offers {recorded}"
        );
        if recorded == 0 {
            assert_eq!(measured, 0, "{name}: reports room where there is none");
        }
    }
}

/// A document written in a script one carrier cannot work with reports zero
/// positions for that carrier and names the script as the reason, while the
/// carrier the cover does not bound stays usable because it places by extending
/// the document rather than being held to the cover. Carrier choice depends on
/// the document, and the report has to say so per carrier.
#[test]
fn a_carrier_with_nothing_to_work_with_reports_zero_while_the_others_do_not() {
    let mut session = Session::open();
    for name in ["cjk_japanese.txt", "cyrillic_russian.txt"] {
        let report = session.run("capacity_report", json!({ "cover": document(name) }));

        let blocked = carrier_report(&report, "homoglyph");
        assert_eq!(blocked["positions"], json!(0), "{name}");
        assert!(
            blocked["zero_reason"]
                .as_str()
                .unwrap()
                .contains("script"),
            "{name}: the reason must say that availability depends on the script"
        );

        // The unbounded carrier is not held to the cover: it stays usable on
        // any script by extending the document. That is what the report states
        // through cover_bounds_writes, not through a raw position count.
        let unbounded = carrier_report(&report, "zero_width");
        assert_eq!(
            unbounded["cover_bounds_writes"],
            json!(false),
            "{name}: zero_width must remain usable because the cover does not bound it"
        );
    }
}

/// The smallest document has no room for a single byte through the carrier
/// that works inside the visible text, and the report says how far short it is
/// rather than simply reporting nothing.
#[test]
fn a_document_too_small_to_hold_a_byte_says_how_far_short_it_is() {
    let mut session = Session::open();
    let report = session.run(
        "capacity_report",
        json!({ "cover": document("minimal_tiny.txt") }),
    );
    let blocked = carrier_report(&report, "homoglyph");
    assert_eq!(blocked["secret_bytes"], json!(0));
    let reason = blocked["zero_reason"].as_str().unwrap();
    assert!(reason.contains("3 positions"), "reason was: {reason}");
    assert!(reason.contains("8"), "reason was: {reason}");
}

/// The report states, per carrier, whether the cover bounds it. A caller
/// planning against secret_bytes needs to know whether that figure is a limit
/// the carrier holds itself to or a point past which the carrier keeps going by
/// extending the document.
#[test]
fn the_report_says_whether_each_carrier_holds_itself_to_the_capacity_it_reported() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");
    let report = session.run("capacity_report", json!({ "cover": cover }));

    for carrier in report["carriers"].as_array().unwrap() {
        let id = carrier["carrier"].as_str().unwrap();
        assert!(
            carrier["cover_bounds_writes"].is_boolean(),
            "{id}: the report must say whether the cover bounds it"
        );

        // Cross-check the claim through a different path: a payload far past
        // secret_bytes must be refused by a carrier the cover bounds.
        if carrier["cover_bounds_writes"] == json!(true) {
            let far_too_much = "x".repeat(
                (carrier["secret_bytes"].as_u64().unwrap() as usize + 1) * 4,
            );
            let attempt = session.request(
                "tools/call",
                json!({
                    "name": "conceal",
                    "arguments": { "cover": cover, "secret": far_too_much, "carriers": [id] }
                }),
            );
            assert_eq!(
                attempt["result"]["isError"],
                json!(true),
                "{id} claims a limit but accepted a payload well past it"
            );
        }
    }
}

/// The honest figure, proven on the document that exposed the old lie: on
/// technical_markdown.md the substitution carrier once reported sixty bytes of
/// room while the heavy frame accepted none, because a framed document is larger
/// than the secret it holds. The report states the figure the engine honours,
/// and under the light frame default (§3.2) this short cover now carries a real
/// secret. For a carrier the cover bounds, exactly secret_bytes is accepted and
/// one byte more is refused with named arithmetic. For the carrier the cover
/// does not bound, the report says so and the carrier places past what the cover
/// frames rather than being held to a number.
#[test]
fn the_reported_secret_capacity_is_the_one_the_engine_accepts() {
    let mut session = Session::open();
    let cover = document("technical_markdown.md");
    let report = session.run("capacity_report", json!({ "cover": &cover }));

    // The substitution carrier has plenty of raw positions here, and under the
    // light frame default the same short cover now frames a usable secret rather
    // than the heavy frame's zero. The figure is still exactly what the engine
    // accepts, proven byte for byte by the boundary loop below.
    let homoglyph = carrier_report(&report, "homoglyph");
    assert!(
        homoglyph["positions"].as_u64().unwrap() > 8,
        "this cover has plenty of raw positions for the substitution carrier"
    );
    assert!(
        homoglyph["secret_bytes"].as_u64().unwrap() > 0,
        "the light frame default makes this short cover usable, not the heavy zero"
    );

    for carrier in report["carriers"].as_array().unwrap() {
        let id = carrier["carrier"].as_str().unwrap();
        let secret_bytes = carrier["secret_bytes"].as_u64().unwrap() as usize;
        let bounded = carrier["cover_bounds_writes"] == json!(true);

        if bounded {
            // Exactly secret_bytes is accepted and reads back.
            if secret_bytes > 0 {
                let placed = session.run(
                    "conceal",
                    json!({
                        "cover": &cover,
                        "secret": "x".repeat(secret_bytes),
                        "carriers": [id]
                    }),
                );
                assert_eq!(
                    placed["round_trip"]["verified"],
                    json!(true),
                    "{id}: the reported {secret_bytes} bytes must be accepted and read back"
                );
            }
            // One byte past it is refused, and the refusal names the placement.
            let attempt = session.request(
                "tools/call",
                json!({
                    "name": "conceal",
                    "arguments": {
                        "cover": &cover,
                        "secret": "x".repeat(secret_bytes + 1),
                        "carriers": [id]
                    }
                }),
            );
            assert_eq!(
                attempt["result"]["isError"],
                json!(true),
                "{id}: one byte past secret_bytes must be refused"
            );
            assert_eq!(
                attempt["result"]["structuredContent"]["error"]["code"],
                json!("placement_refused"),
                "{id}: the refusal past capacity must name the placement"
            );
        } else {
            // The carrier the cover does not bound is not held to a figure: a
            // secret larger than the cover can frame still places, by extending
            // the document.
            assert_eq!(id, "zero_width");
            let framed = carrier["framed_bytes"].as_u64().unwrap() as usize;
            let placed = session.run(
                "conceal",
                json!({
                    "cover": &cover,
                    "secret": "x".repeat(framed + 64),
                    "carriers": [id]
                }),
            );
            assert_eq!(
                placed["round_trip"]["verified"],
                json!(true),
                "{id}: the unbounded carrier must place past what the cover frames"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────
// The happy path
// ─────────────────────────────────────────────────────────────

#[test]
fn the_long_article_carries_a_secret_and_gives_it_back() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");
    let secret = "the board pack goes out on Thursday";

    let placed = session.run(
        "conceal",
        json!({ "cover": cover, "secret": secret, "carriers": ["zero_width"] }),
    );
    assert_eq!(placed["round_trip"]["verified"], json!(true));

    let read = session.run(
        "reveal",
        json!({ "text": placed["stego_text"], "carriers": ["zero_width"] }),
    );
    assert_eq!(read["secret"]["text"], json!(secret));
    assert_eq!(read["integrity_valid"], json!(true));

    // The visible text is untouched.
    let compared = session.run(
        "compare_texts",
        json!({ "left": cover, "right": placed["stego_text"] }),
    );
    assert_eq!(compared["visible_text_identical"], json!(true));
    assert_eq!(compared["identical"], json!(false));
}

#[test]
fn the_long_article_carries_a_protected_secret_and_gives_it_back() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");

    let placed = session.run(
        "conceal",
        json!({
            "cover": cover,
            "secret": "quarterly figures, embargoed",
            "carriers": ["zero_width"],
            "cipher": "aes256_gcm",
            "passcode": "a passcode that never reaches a log"
        }),
    );

    let read = session.run(
        "reveal",
        json!({
            "text": placed["stego_text"],
            "carriers": ["zero_width"],
            "passcode": "a passcode that never reaches a log"
        }),
    );
    assert_eq!(read["secret"]["text"], json!("quarterly figures, embargoed"));
    assert_eq!(read["cipher_used"], json!("aes256_gcm"));
}

const CARRIERS: [&str; 4] = ["zero_width", "whitespace_var", "bidi", "homoglyph"];

/// The fixed payload `try_conceal` places, named so a test can compare its size
/// against a carrier's reported secret_bytes.
const CORPUS_PROBE: &str = "corpus";

/// Try to place a payload and report what happened, as a caller would see it.
fn try_conceal(session: &mut Session, cover: &str, carrier: &str) -> (bool, String) {
    let attempt = session.request(
        "tools/call",
        json!({
            "name": "conceal",
            "arguments": { "cover": cover, "secret": CORPUS_PROBE, "carriers": [carrier] }
        }),
    );
    let structured = &attempt["result"]["structuredContent"];
    let succeeded = attempt["result"]["isError"] == json!(false);
    let code = structured["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_string();
    (succeeded, code)
}

/// Every carrier, on every document: what the capacity report says about
/// whether a payload can be read back must be what the command then does.
///
/// A report saying a carrier accepts N bytes, followed by a command that then
/// takes more than N, is the dishonesty this whole surface exists to prevent.
/// For every bounded carrier and document, a payload larger than the reported
/// secret_bytes must be refused, and every refusal names its cause. The
/// unbounded carrier is not held to a figure: it places by extending the
/// document, so it is only held to naming any refusal it does make.
///
/// The test holds whatever the carriers can currently do, so it keeps its
/// meaning as they change.
#[test]
fn the_capacity_report_and_the_command_always_agree() {
    let mut session = Session::open();
    let probe_len = CORPUS_PROBE.len();

    for name in ALL_DOCUMENTS {
        let cover = document(name);
        let report = session.run("capacity_report", json!({ "cover": cover }));

        for carrier in CARRIERS {
            let entry = carrier_report(&report, carrier);
            let secret_bytes = entry["secret_bytes"].as_u64().unwrap() as usize;
            let bounded = entry["cover_bounds_writes"] == json!(true);
            // try_conceal places a fixed payload of `probe_len` bytes.
            let (succeeded, code) = try_conceal(&mut session, &cover, carrier);

            if bounded && probe_len > secret_bytes {
                assert!(
                    !succeeded,
                    "{name} with {carrier}: the report accepts {secret_bytes} bytes but the command \
                     took a {probe_len} byte payload"
                );
            }
            if !succeeded {
                assert!(
                    code == "round_trip_unverified" || code == "placement_refused",
                    "{name} with {carrier}: refused with '{code}', which names neither cause"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// The known defect, reported rather than worked around
// ─────────────────────────────────────────────────────────────

/// Find a carrier this document has room for but cannot read a payload back
/// from, if the engine currently has one. The report no longer carries a
/// read-back probe (the honest capacity figure made it redundant), so this asks
/// the command directly: place one byte without the round-trip guard, then read
/// it back. A carrier that placed but cannot return the byte is the defect.
fn carrier_that_places_but_cannot_read_back(session: &mut Session, cover: &str) -> Option<String> {
    let report = session.run("capacity_report", json!({ "cover": cover }));
    let candidates: Vec<String> = report["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|carrier| carrier["secret_bytes"].as_u64().unwrap_or(0) > 0)
        .map(|carrier| carrier["carrier"].as_str().unwrap().to_string())
        .collect();

    for carrier in candidates {
        let placed = session.request(
            "tools/call",
            json!({
                "name": "conceal",
                "arguments": {
                    "cover": cover, "secret": "a", "carriers": [carrier.clone()],
                    "require_round_trip": false
                }
            }),
        );
        if placed["result"]["isError"] != json!(false) {
            continue;
        }
        let stego = placed["result"]["structuredContent"]["stego_text"].clone();
        let read = session.request(
            "tools/call",
            json!({
                "name": "reveal",
                "arguments": { "text": stego, "carriers": [carrier.clone()] }
            }),
        );
        let recovered = read["result"]["structuredContent"]["secret"]["text"] == json!("a");
        if !recovered {
            return Some(carrier);
        }
    }
    None
}

/// A document that cannot be read back again is refused, with the reason and
/// with the way to ask for it anyway. Handing it over without saying so would
/// be handing over a failure dressed as a result.
#[test]
fn a_document_that_cannot_be_read_back_is_refused_rather_than_returned() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");

    let Some(carrier) = carrier_that_places_but_cannot_read_back(&mut session, &cover) else {
        // Every carrier can currently read back what it places on this
        // document. The refusal path has nothing to trigger it here, so the
        // thing to prove instead is that the success path really did confirm
        // itself rather than reporting success without checking.
        let placed = session.run(
            "conceal",
            json!({ "cover": cover, "secret": "traceable", "carriers": ["zero_width"] }),
        );
        assert_eq!(placed["round_trip"]["verified"], json!(true));
        return;
    };

    let (code, reason) = session.refuse(
        "conceal",
        json!({ "cover": cover, "secret": "traceable", "carriers": [carrier.clone()] }),
    );
    assert_eq!(code, "round_trip_unverified", "with {carrier}");
    assert!(
        reason.contains("require_round_trip"),
        "the refusal must name the way to ask for it anyway: {reason}"
    );

    // Asked for deliberately, it arrives with the failure attached rather than
    // silently repaired or silently withheld.
    let placed = session.run(
        "conceal",
        json!({
            "cover": cover,
            "secret": "traceable",
            "carriers": [carrier],
            "require_round_trip": false
        }),
    );
    assert_eq!(placed["round_trip"]["verified"], json!(false));
    assert!(placed["round_trip"]["reason"].is_string());
    assert!(placed["stego_text"].is_string());
}

/// The diagnostic reports each stage separately, so a caller learns which one
/// failed rather than being told the whole thing did not work, and its verdict
/// matches what the capacity report predicted for the same carrier.
#[test]
fn the_plan_check_reports_each_stage_and_agrees_with_the_capacity_report() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");
    let report = session.run("capacity_report", json!({ "cover": cover }));

    for carrier in ["zero_width", "whitespace_var", "bidi", "homoglyph"] {
        // roundtrip_check places the default eight byte probe. A carrier
        // recovers it exactly when it accepts eight bytes: a bounded carrier
        // with room, or the unbounded carrier that overflows to fit it.
        let entry = carrier_report(&report, carrier);
        let predicted = entry["cover_bounds_writes"] == json!(false)
            || entry["secret_bytes"].as_u64().unwrap() >= 8;

        let checked = session.run(
            "roundtrip_check",
            json!({ "cover": cover, "carriers": [carrier] }),
        );
        assert_eq!(checked["composition"]["passed"], json!(true), "{carrier}");
        assert_eq!(checked["placement"]["passed"], json!(true), "{carrier}");
        assert_eq!(
            checked["payload_recovered_exactly"],
            json!(predicted),
            "{carrier}: the plan check and the capacity report disagree"
        );
    }
}

/// A document with no room refuses at placement, naming the shortfall.
#[test]
fn a_document_with_no_room_refuses_at_placement() {
    let mut session = Session::open();
    let (code, reason) = session.refuse(
        "conceal",
        json!({
            "cover": document("minimal_tiny.txt"),
            "secret": "far too much for this document",
            "carriers": ["homoglyph"]
        }),
    );
    assert_eq!(code, "placement_refused");
    assert!(
        reason.to_lowercase().contains("capacity"),
        "reason was: {reason}"
    );
}

/// A document that arrived already holding material is reported as such
/// before anything is attempted on it, so a caller learns it is working on a
/// document with a history rather than a blank one.
#[test]
fn a_document_that_already_carries_something_is_flagged_before_anything_is_attempted() {
    let mut session = Session::open();
    let cover = document("already_carrying.txt");
    let recorded = manifest_entry("already_carrying.txt")["preexisting_invisible"]
        .as_u64()
        .unwrap();
    assert!(recorded > 0, "this document is the one with a history");

    // The report notices it.
    let seen = session.run("inspect", json!({ "text": cover }));
    assert!(
        seen["overall_score"].as_f64().unwrap() > 0.0,
        "a document holding material must not be reported as holding none"
    );

    // At least one channel of this document already holds material that mixes
    // with anything placed in it, so at least one carrier's command refuses
    // rather than returning the mixture. The refusal names the mixing or the
    // room, whichever the command reaches first; both are honest answers and
    // neither is a result.
    let mut disturbed: Vec<&str> = Vec::new();
    for carrier in CARRIERS {
        let (succeeded, code) = try_conceal(&mut session, &cover, carrier);
        if !succeeded {
            assert!(
                code == "round_trip_unverified" || code == "placement_refused",
                "{carrier} refused with '{code}', which names neither cause"
            );
            disturbed.push(carrier);
        }
    }
    assert!(
        !disturbed.is_empty(),
        "this document holds material before anything is placed in it, and at least one channel must say so"
    );
}

// ─────────────────────────────────────────────────────────────
// Inspection and analysis
// ─────────────────────────────────────────────────────────────

#[test]
fn inspecting_a_prepared_document_reports_its_shape_without_opening_it() {
    let mut session = Session::open();
    let placed = session.run(
        "conceal",
        json!({
            "cover": document("en_long_article.txt"),
            "secret": "not to be read here",
            "carriers": ["zero_width"],
            "cipher": "chacha20_poly1305",
            "passcode": "the passcode"
        }),
    );

    let seen = session.run("inspect", json!({ "text": placed["stego_text"] }));
    assert_eq!(seen["decrypted"], json!(false));
    let entry = seen["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["carrier"] == json!("zero_width"))
        .unwrap();
    assert_eq!(
        entry["envelope"]["cipher_declared"],
        json!("chacha20_poly1305")
    );
    assert!(entry["envelope"]["payload_bytes"].as_u64().unwrap() > 0);
    assert!(seen["chain_summary"]["carriers_responding"]
        .as_array()
        .unwrap()
        .contains(&json!("zero_width")));

    let rendered = seen.to_string();
    assert!(!rendered.contains("not to be read here"));
    assert!(!rendered.contains("the passcode"));
}

#[test]
fn every_document_gets_a_full_report() {
    let mut session = Session::open();
    for name in ALL_DOCUMENTS {
        let report = session.run("analyze", json!({ "text": document(name) }));
        assert!(report["verdict"].is_string(), "{name}");
        assert!(report["suspicion_score"].is_number(), "{name}");
        assert!(report["unicode_analysis"]["total_chars"].as_u64().unwrap() > 0, "{name}");
        assert!(report["statistics"]["shannon_entropy"].is_number(), "{name}");
        assert!(report["summary"].is_array(), "{name}");
    }
}

/// The document that arrives already carrying invisible material is reported
/// as carrying it, with the count the manifest recorded.
#[test]
fn a_document_that_arrives_carrying_something_is_reported_as_such() {
    let mut session = Session::open();
    let entry = manifest_entry("already_carrying.txt");
    let recorded = entry["preexisting_invisible"].as_u64().unwrap();

    let report = session.run(
        "analyze",
        json!({ "text": document("already_carrying.txt") }),
    );
    assert_eq!(
        report["unicode_analysis"]["invisible_chars"],
        json!(recorded)
    );
    assert_ne!(report["verdict"], json!("Clean"));
}

// ─────────────────────────────────────────────────────────────
// Cleaning, and the document it must not corrupt
// ─────────────────────────────────────────────────────────────

/// Cleaning returns the original document once the carried material is gone.
#[test]
fn cleaning_a_prepared_document_gives_the_original_back() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");
    let placed = session.run(
        "conceal",
        json!({ "cover": cover, "secret": "removable", "carriers": ["zero_width"] }),
    );

    let cleaned = session.run("sanitize", json!({ "text": placed["stego_text"] }));
    assert_eq!(cleaned["text"], json!(cover));
    assert_eq!(cleaned["changed"], json!(true));
    assert!(cleaned["chars_removed"].as_u64().unwrap() > 0);
}

/// A document written in Cyrillic is not a marked document, and the cleaning
/// that would rewrite visible characters must refuse to run on it. Running it
/// would rewrite the writing itself.
#[test]
fn cleaning_never_rewrites_a_document_that_was_never_marked() {
    let mut session = Session::open();
    let russian = document("cyrillic_russian.txt");

    // Asked for without saying so: refused because it rewrites visible text.
    let (code, reason) = session.refuse(
        "sanitize",
        json!({ "text": russian, "channels": ["homoglyph"] }),
    );
    assert_eq!(code, "visible_rewrite_refused");
    assert!(reason.contains("allow_visible_text_rewrite"));

    // Asked for deliberately: still refused, because this document shows no
    // sign of the marking the operation would remove.
    let (code, reason) = session.refuse(
        "sanitize",
        json!({
            "text": russian,
            "channels": ["homoglyph"],
            "allow_visible_text_rewrite": true
        }),
    );
    assert_eq!(code, "no_marking_found");
    assert!(reason.contains("rewrite"), "reason was: {reason}");

    // And the default cleaning leaves it exactly as it was.
    let cleaned = session.run("sanitize", json!({ "text": russian }));
    assert_eq!(cleaned["text"], json!(russian));
    assert_eq!(cleaned["changed"], json!(false));
}

/// The same operation is allowed on a document that does show the marking,
/// which is what makes the refusal above a guard rather than a blanket ban.
#[test]
fn cleaning_runs_on_a_document_that_does_show_the_marking() {
    let mut session = Session::open();
    let marked = session.run(
        "mark_batch",
        json!({
            "text": document("en_long_article.txt"),
            "recipients": ["desk-a"],
            "salt": "distribution-2026-08"
        }),
    );
    let copy = marked["copies"][0]["text"].clone();

    let cleaned = session.run(
        "sanitize",
        json!({
            "text": copy,
            "channels": ["homoglyph"],
            "allow_visible_text_rewrite": true
        }),
    );
    assert_eq!(cleaned["changed"], json!(true));
    assert_eq!(cleaned["text"], json!(document("en_long_article.txt")));
}

/// Normalising destroys carried material, so it refuses unless the loss is
/// accepted in the request.
#[test]
fn normalising_a_carrying_document_refuses_before_it_destroys_anything() {
    let mut session = Session::open();
    let placed = session.run(
        "conceal",
        json!({
            "cover": document("fr_accented.txt"),
            "secret": "accents",
            "carriers": ["zero_width"]
        }),
    );

    let (code, _) = session.refuse(
        "normalize_text",
        json!({ "text": placed["stego_text"], "remove_accents": true }),
    );
    assert_eq!(code, "payload_loss_refused");

    let normalised = session.run(
        "normalize_text",
        json!({
            "text": placed["stego_text"],
            "remove_accents": true,
            "accept_payload_loss": true
        }),
    );
    assert_eq!(normalised["changed"], json!(true));
}

// ─────────────────────────────────────────────────────────────
// Distribution and tracing
// ─────────────────────────────────────────────────────────────

#[test]
fn a_distribution_produces_one_copy_per_recipient_and_traces_a_leak_back() {
    let mut session = Session::open();
    let recipients = ["board-chair", "finance-lead", "counsel", "auditor"];

    let batch = session.run(
        "mark_batch",
        json!({
            "text": document("en_long_article.txt"),
            "recipients": recipients,
            "salt": "board-pack-2026-08"
        }),
    );
    let copies = batch["copies"].as_array().unwrap();
    assert_eq!(copies.len(), recipients.len());
    assert!(batch["mark_bits"].as_u64().unwrap() > 0);

    // Every copy reads the same to a person.
    let original = document("en_long_article.txt");
    for copy in copies {
        let compared = session.run(
            "compare_texts",
            json!({ "left": original, "right": copy["text"] }),
        );
        assert_eq!(compared["identical"], json!(false));
    }

    // A leaked copy comes back to its recipient.
    let leaked = copies[2]["text"].clone();
    let traced = session.run(
        "trace_origin",
        json!({ "text": leaked, "registry": batch["registry"] }),
    );
    assert_eq!(traced["identified"], json!(true));
    assert_eq!(traced["recipient_id"], json!("counsel"));
    assert_eq!(traced["confidence"], json!(1.0));
}

/// Tracing takes no passcode. That is the whole point of the mark path, and it
/// is the property that would be lost first if the two paths were merged.
#[test]
fn tracing_needs_no_passcode() {
    let mut session = Session::open();
    let batch = session.run(
        "mark_batch",
        json!({
            "text": document("technical_markdown.md"),
            "recipients": ["reviewer-one", "reviewer-two"],
            "salt": "draft-review"
        }),
    );
    let traced = session.run(
        "trace_origin",
        json!({ "text": batch["copies"][1]["text"], "registry": batch["registry"] }),
    );
    assert_eq!(traced["recipient_id"], json!("reviewer-two"));
}

/// An unrelated document is reported as unidentified rather than matched to
/// whichever recipient happens to be closest.
#[test]
fn an_unrelated_document_is_reported_as_unidentified() {
    let mut session = Session::open();
    let batch = session.run(
        "mark_batch",
        json!({
            "text": document("en_long_article.txt"),
            "recipients": ["one", "two"],
            "salt": "salt"
        }),
    );
    let traced = session.run(
        "trace_origin",
        json!({ "text": document("fr_accented.txt"), "registry": batch["registry"] }),
    );
    assert_eq!(traced["identified"], json!(false));
    assert_eq!(traced["recipient_id"], Value::Null);
}

/// A document that offers the mark path nothing to work with is refused, with
/// the reason, rather than quietly falling back to something else.
#[test]
fn a_distribution_is_refused_on_a_document_that_cannot_hold_a_mark() {
    let mut session = Session::open();
    for name in ["cjk_japanese.txt", "cyrillic_russian.txt", "minimal_tiny.txt"] {
        let (code, reason) = session.refuse(
            "mark_batch",
            json!({ "text": document(name), "recipients": ["only-one"], "salt": "s" }),
        );
        assert_eq!(code, "marking_refused", "{name}");
        assert!(!reason.is_empty(), "{name}");
    }
}

// ─────────────────────────────────────────────────────────────
// Authorship
// ─────────────────────────────────────────────────────────────

#[test]
fn an_authorship_claim_survives_a_full_corpus_document() {
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
    assert_eq!(signed["round_trip"]["verified"], json!(true));

    let checked = session.run(
        "authorship_verify",
        json!({
            "text": signed["signed_text"],
            "public_key_base64": keys["public_key_base64"],
        }),
    );
    assert_eq!(checked["verified"], json!(true));
    assert_eq!(checked["claim"]["author"], json!("Hope 'n Mind"));
}

/// A claim that was removed fails its check, and a claim that is still there
/// cannot be written over. A claim that survived removal would be worth
/// nothing, and a second layer written into its channel would leave a document
/// that answers neither for the claim nor for the layer.
///
/// The second half of this once asserted that placing into the occupied
/// channel produced a mixture that then failed verification. The engine now
/// refuses that placement by name instead, before any text is produced, which
/// is the stronger answer: nothing is corrupted, so nothing has to be caught
/// afterwards. The property tested is what should hold, not what happened to
/// be true before.
#[test]
fn removing_a_claim_breaks_its_check_and_writing_over_it_is_refused() {
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

    // Clearing the channel the claim travels in removes it entirely.
    let stripped = session.run(
        "sanitize",
        json!({ "text": signed["signed_text"], "channels": ["zero_width"] }),
    );
    let (code, _) = session.refuse(
        "authorship_verify",
        json!({ "text": stripped["text"], "public_key_base64": keys["public_key_base64"] }),
    );
    assert_eq!(code, "verification_refused");

    // Placing into the channel the claim occupies is refused by name. The
    // refusal happens before any text is produced, so require_round_trip has
    // nothing to reach: there is no document to hand over, verified or not.
    let (code, reason) = session.refuse(
        "conceal",
        json!({
            "cover": signed["signed_text"],
            "secret": "interference",
            "carriers": ["zero_width"],
            "require_round_trip": false
        }),
    );
    assert_eq!(code, "placement_refused");
    assert!(
        reason.contains("already contains") && reason.contains("alphabet"),
        "the refusal must name the material already in the channel: {reason}"
    );

    // And the claim it refused to write over is untouched by the attempt.
    let checked = session.run(
        "authorship_verify",
        json!({
            "text": signed["signed_text"],
            "public_key_base64": keys["public_key_base64"],
        }),
    );
    assert_eq!(checked["verified"], json!(true));
}

/// Editing the visible writing around a claim invalidates it, because the claim
/// is now signed over the document and not only over itself. Verification of an
/// edited document refuses by name, and the refusal states that the visible
/// text has been altered since the claim was attached rather than confirming a
/// document that changed under the claim.
///
/// This inverts the earlier contract, which asserted that editing left the
/// claim confirmed. That behaviour was backlog item F12 and has been corrected:
/// the signed claim now carries a hash of the stripped cover, so any visible
/// edit is detected. The property tested here is what should hold, not what
/// happened to be true before the fix.
#[test]
fn editing_the_surrounding_text_invalidates_a_document_bound_claim() {
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

    // Unedited, the claim verifies against its own document.
    let checked = session.run(
        "authorship_verify",
        json!({
            "text": signed["signed_text"],
            "public_key_base64": keys["public_key_base64"],
        }),
    );
    assert_eq!(checked["verified"], json!(true));

    // Edited, verification refuses and names the alteration rather than passing.
    let edited = format!(
        "{} One more sentence, added by somebody else.",
        signed["signed_text"].as_str().unwrap()
    );
    let (code, reason) = session.refuse(
        "authorship_verify",
        json!({ "text": edited, "public_key_base64": keys["public_key_base64"] }),
    );
    assert_eq!(code, "verification_refused");
    assert!(
        reason.contains("hash mismatch") || reason.contains("altered"),
        "the refusal must name the alteration, reason was: {reason}"
    );
}

/// A document with no room for a claim is refused with the shortfall named.
///
/// The carrier here is one the cover bounds. The claim is far larger than a
/// short cover can frame, so the carrier refuses up front rather than placing.
/// The unbounded carrier could not stand in for this: it is never held to the
/// cover, it places by extending the document, so a short cover is never "too
/// small" for it.
#[test]
fn a_document_too_small_for_a_claim_is_refused() {
    let mut session = Session::open();
    let keys = session.run("authorship_keypair", json!({}));
    let (code, reason) = session.refuse(
        "authorship_sign",
        json!({
            "cover": document("en_short.txt"),
            "author": "Hope 'n Mind",
            "private_key_base64": keys["private_key_base64"],
            "carrier": "homoglyph",
        }),
    );
    assert_eq!(code, "signing_refused");
    assert!(reason.to_lowercase().contains("capacity"), "reason was: {reason}");
}

// ─────────────────────────────────────────────────────────────
// Output
// ─────────────────────────────────────────────────────────────

/// The last step of a session hands back something a person can be given, and
/// says what it is handing over.
#[test]
fn output_is_rendered_with_its_own_fingerprint_and_verdict() {
    let mut session = Session::open();
    let placed = session.run(
        "conceal",
        json!({
            "cover": document("technical_markdown.md"),
            "secret": "for redistribution",
            "carriers": ["zero_width"]
        }),
    );

    for format in ["plain", "markdown", "html", "json", "base64", "data_uri"] {
        let rendered = session.run(
            "render",
            json!({ "text": placed["stego_text"], "format": format, "title": "Release note" }),
        );
        assert_eq!(rendered["format"], json!(format));
        assert!(!rendered["output"].as_str().unwrap().is_empty(), "{format}");
        assert_eq!(
            rendered["integrity"]["sha256"].as_str().unwrap().len(),
            64,
            "{format}"
        );
        assert!(rendered["report"]["verdict"].is_string(), "{format}");
    }
}

/// What comes out of the plain rendering is exactly what went in, so the
/// carried material survives the last step.
#[test]
fn the_rendered_document_still_carries_what_was_placed_in_it() {
    let mut session = Session::open();
    let placed = session.run(
        "conceal",
        json!({
            "cover": document("en_long_article.txt"),
            "secret": "survives rendering",
            "carriers": ["zero_width"]
        }),
    );
    let rendered = session.run(
        "render",
        json!({ "text": placed["stego_text"], "format": "plain" }),
    );
    let read = session.run(
        "reveal",
        json!({ "text": rendered["output"], "carriers": ["zero_width"] }),
    );
    assert_eq!(read["secret"]["text"], json!("survives rendering"));
}

// ─────────────────────────────────────────────────────────────
// The whole loop
// ─────────────────────────────────────────────────────────────

/// One session, from asking what is available to handing back a finished
/// document, over the surface an agent actually reaches.
#[test]
fn a_full_session_runs_from_discovery_to_a_finished_document() {
    let mut session = Session::open();
    let cover = document("en_long_article.txt");

    // What is available.
    let capabilities = session.run("capabilities_list", json!({}));
    assert!(!capabilities["carriers"].as_array().unwrap().is_empty());

    // What this document can hold.
    let report = session.run("capacity_report", json!({ "cover": cover }));
    let usable: Vec<String> = report["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|carrier| {
            carrier["secret_bytes"].as_u64().unwrap() > 0
                || carrier["cover_bounds_writes"] == json!(false)
        })
        .map(|carrier| carrier["carrier"].as_str().unwrap().to_string())
        .collect();
    assert!(!usable.is_empty(), "this document must support something");

    // Does the plan work on this document.
    let checked = session.run(
        "roundtrip_check",
        json!({ "cover": cover, "carriers": [usable[0].clone()] }),
    );
    assert_eq!(checked["payload_recovered_exactly"], json!(true));

    // Do it.
    let placed = session.run(
        "conceal",
        json!({
            "cover": cover,
            "secret": "the whole loop",
            "carriers": [usable[0].clone()],
            "cipher": "chacha20_poly1305",
            "passcode": "loop passcode"
        }),
    );

    // What does it look like from outside.
    let seen = session.run("inspect", json!({ "text": placed["stego_text"] }));
    assert!(seen["overall_score"].as_f64().unwrap() > 0.0);

    // Hand it over.
    let rendered = session.run(
        "render",
        json!({ "text": placed["stego_text"], "format": "plain" }),
    );

    // And it still works at the far end.
    let read = session.run(
        "reveal",
        json!({
            "text": rendered["output"],
            "carriers": [usable[0].clone()],
            "passcode": "loop passcode"
        }),
    );
    assert_eq!(read["secret"]["text"], json!("the whole loop"));

    // Nothing said along the way carried the secret or the passcode.
    for said in [&capabilities, &report, &checked, &seen] {
        let rendered = said.to_string();
        assert!(!rendered.contains("loop passcode"));
        assert!(!rendered.contains("the whole loop"));
    }
}

/// Settings reached over the surface behave the same as anywhere else: a bad
/// value changes nothing and comes back named.
#[test]
fn settings_are_reachable_over_the_surface_and_refuse_bad_values() {
    let mut session = Session::open();
    let read = session.run("settings_read", json!({}));
    assert_eq!(read["settings"]["language"], json!("en"));
    assert!(read["constraints"]["density"]["mark"]["minimum"].is_number());

    let (code, reason) = session.refuse(
        "settings_update",
        json!({ "settings": { "density": { "conceal": 5.0 } } }),
    );
    assert_eq!(code, "settings_rejected");
    assert!(reason.contains("density.conceal"));

    let unchanged = session.run("settings_read", json!({}));
    assert_eq!(unchanged["settings"]["density"]["conceal"], json!(0.25));
}

// ─────────────────────────────────────────────────────────────
// Provenance
// ─────────────────────────────────────────────────────────────

/// A signed provenance record is attached to a corpus document, read back and
/// confirmed, then the document is edited and the same record is reported as no
/// longer holding, with the alteration named. This is the real path an agent
/// reaches over the channel: sign, verify, tamper, verify fails by name.
#[test]
fn a_provenance_record_signs_verifies_and_names_a_tampered_document_over_the_channel() {
    let mut session = Session::open();
    let keys = session.run("authorship_keypair", json!({}));
    let cover = document("en_long_article.txt");

    let signed = session.run(
        "provenance_sign",
        json!({
            "cover": cover,
            "assertions": [
                { "kind": "human_authorship", "author": "Hope 'n Mind" },
                { "kind": "integrity" }
            ],
            "private_key_base64": keys["private_key_base64"],
        }),
    );
    assert_eq!(signed["binding"], json!("detached"));
    assert_eq!(signed["round_trip"]["verified"], json!(true));

    let verified = session.run(
        "provenance_verify",
        json!({
            "document": cover,
            "sidecar_base64": signed["sidecar"]["base64"],
            "trusted_keys_base64": [keys["public_key_base64"]],
        }),
    );
    assert_eq!(verified["provenance_holds"], json!(true));
    assert!(verified["claims"][0]["assertion_kinds"]
        .as_array()
        .unwrap()
        .contains(&json!("human_authorship")));

    let edited = format!("{cover} A sentence appended after the record was made.");
    let tampered = session.run(
        "provenance_verify",
        json!({
            "document": edited,
            "sidecar_base64": signed["sidecar"]["base64"],
            "trusted_keys_base64": [keys["public_key_base64"]],
        }),
    );
    assert_eq!(tampered["provenance_holds"], json!(false));
    assert_eq!(tampered["claims"][0]["document_unaltered"], json!(false));
    assert!(tampered["claims"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f.as_str().unwrap().contains("document altered")));
}

/// An AI-generated disclosure carried within the document itself (Article 50)
/// verifies end to end and reports its robustness as measured, never higher.
#[test]
fn an_in_band_ai_disclosure_verifies_over_the_channel() {
    let mut session = Session::open();
    let keys = session.run("authorship_keypair", json!({}));
    let cover = document("en_long_article.txt");

    let signed = session.run(
        "provenance_sign",
        json!({
            "cover": cover,
            "assertions": [{ "kind": "ai_generated", "model": "assistant", "provider": "lab" }],
            "private_key_base64": keys["private_key_base64"],
            "binding": "in_band",
            "carrier": "zero_width",
        }),
    );
    assert_eq!(signed["measured_robustness"]["class"], json!("BestEffort"));

    let verified = session.run(
        "provenance_verify",
        json!({
            "document": signed["marked_text"],
            "trusted_keys_base64": [keys["public_key_base64"]],
            "carriers": ["zero_width"],
        }),
    );
    assert_eq!(verified["provenance_holds"], json!(true));
    assert_eq!(verified["claims"][0]["binding"], json!("in_band"));
}

// ─────────────────────────────────────────────────────────────
// Document sovereignty (the AI-regulation tool)
// ─────────────────────────────────────────────────────────────
//
// The two C2PA fixtures are the same genuine assets the core AR-2 tests use:
// a signed JPEG whose signature is intact but whose certificate is outside any
// trust list, and a plain image with no credential. They are referenced here so
// the surface is driven over real bytes, not a stub.

const NO_MANIFEST_PNG: &[u8] =
    include_bytes!("../../stegano-core/tests/fixtures/c2pa/no_manifest.png");
const GENUINE_SIGNED_JPEG: &[u8] =
    include_bytes!("../../stegano-core/tests/fixtures/c2pa/genuine_signed.jpg");

/// Inspecting a document that arrived already carrying material reports its
/// marks by class and count, over the surface an agent actually reaches.
#[test]
fn document_inspect_reports_the_marks_a_document_carries() {
    let mut session = Session::open();
    let report = session.run(
        "document_inspect",
        json!({ "document": document("already_carrying.txt") }),
    );

    let class_count = |id: &str| {
        report["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap_or_else(|| panic!("class {id} must be listed"))["count"]
            .as_u64()
            .unwrap()
    };
    // The document holds two zero-width and two whitespace-variation marks.
    assert_eq!(class_count("zero_width"), 2);
    assert_eq!(class_count("whitespace_var"), 2);
    assert_eq!(class_count("homoglyph"), 0);
    assert!(report["summary"].is_array());
}

/// Cleaning the chosen class removes exactly it and leaves the rest, and the
/// honest residual note is always present. Cleaning a class that is absent
/// leaves the document byte-identical, which is the trap AR-1 exists to avoid.
#[test]
fn document_clean_removes_the_chosen_class_and_leaves_the_rest() {
    let mut session = Session::open();
    let original = document("already_carrying.txt");

    let cleaned = session.run(
        "document_clean",
        json!({ "document": original, "classes": ["zero_width"] }),
    );
    let removed = cleaned["removed"].as_array().unwrap();
    assert_eq!(removed.len(), 1, "only the chosen class is reported");
    assert_eq!(removed[0]["id"], json!("zero_width"));
    assert_eq!(removed[0]["count"], json!(2));
    assert_eq!(cleaned["altered"], json!(true));

    let text = cleaned["cleaned_text"].as_str().unwrap();
    assert!(
        !text.contains('\u{200B}') && !text.contains('\u{200C}'),
        "the chosen class is gone"
    );
    assert!(
        text.contains('\u{2060}') && text.contains('\u{FEFF}'),
        "the class that was not chosen survives untouched"
    );
    // The residual note is always present and honest about native scope.
    let residual = cleaned["residual"].as_array().unwrap();
    assert!(residual.len() >= 3);
    assert!(residual
        .iter()
        .any(|note| note.as_str().unwrap().to_lowercase().contains("statistical")));

    // Cleaning a class the document does not carry changes not a single byte.
    let untouched = session.run(
        "document_clean",
        json!({ "document": original, "classes": ["homoglyph"] }),
    );
    assert_eq!(untouched["cleaned_text"], json!(original));
    assert_eq!(untouched["altered"], json!(false));
}

/// A file with no content credential is reported Absent, not raised as an
/// error, over the surface.
#[test]
fn c2pa_inspect_reports_absent_on_a_file_without_a_credential() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let report = session.run(
        "c2pa_inspect",
        json!({ "file_base64": B64.encode(NO_MANIFEST_PNG), "format_hint": "image/png" }),
    );
    assert_eq!(report["present"], json!(false));
    assert_eq!(report["verdict"], json!("absent"));
    assert!(report["manifest"].is_null());
    assert!(report["failures"].as_array().unwrap().is_empty());
}

/// The verdict mirrors the conformant reader's validation state and is never
/// overstated: a genuine test-signed file reads signature-valid with the trust
/// anchor not established.
#[test]
fn c2pa_inspect_mirrors_the_readers_verdict_and_does_not_overstate_trust() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let report = session.run(
        "c2pa_inspect",
        json!({ "file_base64": B64.encode(GENUINE_SIGNED_JPEG), "format_hint": "image/jpeg" }),
    );
    assert_eq!(report["present"], json!(true));
    assert_eq!(report["verdict"], json!("signature_valid"));
    assert_eq!(report["trust_anchor_established"], json!(false));
    assert_eq!(report["validation_state"], json!("Valid"));
}

// ─────────────────────────────────────────────────────────────
// File inspect and clean (the file layer over the surface)
// ─────────────────────────────────────────────────────────────
//
// The fixture is a plain-text document provably marked with the core's own
// zero-width carrier, supplied to the surface as base64 bytes with a format
// hint, exactly as an agent would send a real file.

/// A cover long enough for the zero-width carrier to place a byte of payload.
const FILE_COVER: &str = "The quick brown fox jumps over the lazy dog near the bank";

/// `FILE_COVER` marked with a real zero-width payload the core carrier placed.
fn file_marked() -> String {
    use stegano_core::stego::ZeroWidth;
    use stegano_core::traits::StegoMethod;
    let marked = ZeroWidth::new().encode(FILE_COVER, b"x").unwrap();
    assert_ne!(marked, FILE_COVER, "the fixture must actually carry a mark");
    marked
}

/// Inspecting a marked document file over base64 reports the zero-width class.
#[test]
fn file_inspect_over_base64_reports_the_class() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let report = session.run(
        "file_inspect",
        json!({ "file_base64": B64.encode(file_marked().as_bytes()), "format": "txt" }),
    );
    assert_eq!(report["format"], json!("text"));
    let zw = report["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!("zero_width"))
        .expect("zero_width class listed");
    assert!(zw["count"].as_u64().unwrap() > 0);
}

/// Cleaning a marked document file over base64 returns cleaned bytes that
/// re-inspect clean, with the removed counts, the text-native cleaned text, and
/// the honest residual note.
#[test]
fn file_clean_over_base64_returns_bytes_that_reinspect_clean() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let cleaned = session.run(
        "file_clean",
        json!({
            "file_base64": B64.encode(file_marked().as_bytes()),
            "format": "txt",
            "classes": ["zero_width"]
        }),
    );
    assert_eq!(cleaned["altered"], json!(true));
    assert_eq!(cleaned["format"], json!("text"));
    let removed = cleaned["removed"].as_array().unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["id"], json!("zero_width"));
    assert!(removed[0]["count"].as_u64().unwrap() > 0);
    // Text-native, so the cleaned text is the document itself: the cover again.
    assert_eq!(cleaned["cleaned_text"], json!(FILE_COVER));
    // The honest residual note is always present.
    assert!(cleaned["residual"].as_array().unwrap().len() >= 3);

    // The cleaned base64 re-inspects clean over the surface.
    let cleaned_b64 = cleaned["cleaned_file_base64"].as_str().unwrap();
    let rechecked = session.run(
        "file_inspect",
        json!({ "file_base64": cleaned_b64, "format": "txt" }),
    );
    let zw = rechecked["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!("zero_width"))
        .unwrap();
    assert_eq!(zw["count"], json!(0));
}

/// An unsupported format is a named refusal, not a silent empty report.
#[test]
fn file_inspect_refuses_an_unsupported_format_by_name() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let (code, reason) = session.refuse(
        "file_inspect",
        json!({ "file_base64": B64.encode(b"whatever the bytes"), "format": "pdf" }),
    );
    assert_eq!(code, "file_unsupported_format");
    assert!(
        reason.to_lowercase().contains("unsupported") && reason.contains("pdf"),
        "the refusal must name the unsupported format: {reason}"
    );
}

/// Cleaning an HTML document is a named refusal surfaced from the transform.
#[test]
fn file_clean_refuses_html_by_name() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let html = b"<html><body><p>Body with a mark.</p></body></html>";
    let (code, reason) = session.refuse(
        "file_clean",
        json!({ "file_base64": B64.encode(html), "format": "html", "classes": ["zero_width"] }),
    );
    assert_eq!(code, "file_clean_refused");
    assert!(
        reason.contains("HTML"),
        "the refusal must name the HTML format: {reason}"
    );
}

// ─────────────────────────────────────────────────────────────
// File analyze, conceal, convert and metadata (the file capabilities)
// ─────────────────────────────────────────────────────────────
//
// Four operations over a real document supplied as base64 bytes with a format
// hint. Each wraps the file layer's own public API. Fixtures are a provably
// marked plain-text document, a generous cover the concealment ceiling admits,
// a Markdown source with a heading, and an embedded minimal DOCX carrying known
// docProps (so no zip dependency is needed in this crate).

/// A cover generous enough for the concealment density ceiling to admit a small
/// secret. The file conceal runs under the Conceal mission, like the desktop, so
/// a short cover offers no room; this repeated sentence gives the carrier slack.
fn conceal_cover() -> String {
    "Every record in the ledger is kept legible for the whole review team. ".repeat(80)
}

/// A minimal but valid DOCX carrying known docProps (title, creator, keywords, a
/// custom property), base64 encoded and embedded so the test needs no zip crate.
const FIXTURE_DOCX_B64: &str = "UEsDBBQAAAAAAE8NG13muHRrYgAAAGIAAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbDw/eG1sIHZlcnNpb249IjEuMCI/PjxUeXBlcyB4bWxucz0iaHR0cDovL3NjaGVtYXMub3BlbnhtbGZvcm1hdHMub3JnL3BhY2thZ2UvMjAwNi9jb250ZW50LXR5cGVzIi8+UEsDBBQAAAAAAE8NG12QJd+9nAAAAJwAAAARAAAAd29yZC9kb2N1bWVudC54bWw8dzpkb2N1bWVudCB4bWxuczp3PSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvd29yZHByb2Nlc3NpbmdtbC8yMDA2L21haW4iPjx3OmJvZHk+PHc6cD48dzpyPjx3OnQ+Qm9keSB0ZXh0Ljwvdzp0PjwvdzpyPjwvdzpwPjwvdzpib2R5Pjwvdzpkb2N1bWVudD5QSwMEFAAAAAAATw0bXeCHdgsIAgAACAIAABEAAABkb2NQcm9wcy9jb3JlLnhtbDw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz48Y3A6Y29yZVByb3BlcnRpZXMgeG1sbnM6Y3A9Imh0dHA6Ly9zY2hlbWFzLm9wZW54bWxmb3JtYXRzLm9yZy9wYWNrYWdlLzIwMDYvbWV0YWRhdGEvY29yZS1wcm9wZXJ0aWVzIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOmRjdGVybXM9Imh0dHA6Ly9wdXJsLm9yZy9kYy90ZXJtcy8iIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiPjxkYzp0aXRsZT5RdWFydGVybHkgUmVwb3J0PC9kYzp0aXRsZT48ZGM6Y3JlYXRvcj5BZGEgTG92ZWxhY2U8L2RjOmNyZWF0b3I+PGNwOmtleXdvcmRzPmZpbmFuY2UsIHEzLCBpbnRlcm5hbDwvY3A6a2V5d29yZHM+PGRjdGVybXM6Y3JlYXRlZCB4c2k6dHlwZT0iZGN0ZXJtczpXM0NEVEYiPjIwMjYtMDEtMDJUMDk6MDA6MDBaPC9kY3Rlcm1zOmNyZWF0ZWQ+PC9jcDpjb3JlUHJvcGVydGllcz5QSwMEFAAAAAAATw0bXRRHFnnwAAAA8AAAABAAAABkb2NQcm9wcy9hcHAueG1sPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/PjxQcm9wZXJ0aWVzIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvb2ZmaWNlRG9jdW1lbnQvMjAwNi9leHRlbmRlZC1wcm9wZXJ0aWVzIj48QXBwbGljYXRpb24+TWljcm9zb2Z0IE9mZmljZSBXb3JkPC9BcHBsaWNhdGlvbj48Q29tcGFueT5Ib3BlIG4gTWluZDwvQ29tcGFueT48L1Byb3BlcnRpZXM+UEsDBBQAAAAAAE8NG11ZhXRNdQEAAHUBAAATAAAAZG9jUHJvcHMvY3VzdG9tLnhtbDw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz48UHJvcGVydGllcyB4bWxucz0iaHR0cDovL3NjaGVtYXMub3BlbnhtbGZvcm1hdHMub3JnL29mZmljZURvY3VtZW50LzIwMDYvY3VzdG9tLXByb3BlcnRpZXMiIHhtbG5zOnZ0PSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvb2ZmaWNlRG9jdW1lbnQvMjAwNi9kb2NQcm9wc1ZUeXBlcyI+PHByb3BlcnR5IGZtdGlkPSJ7RDVDREQ1MDUtMkU5Qy0xMDFCLTkzOTctMDgwMDJCMkNGOUFFfSIgcGlkPSIyIiBuYW1lPSJDbGFzc2lmaWNhdGlvbiI+PHZ0Omxwd3N0cj5Db25maWRlbnRpYWw8L3Z0Omxwd3N0cj48L3Byb3BlcnR5PjwvUHJvcGVydGllcz5QSwECFAAUAAAAAABPDRtd5rh0a2IAAABiAAAAEwAAAAAAAAAAAAAAgAEAAAAAW0NvbnRlbnRfVHlwZXNdLnhtbFBLAQIUABQAAAAAAE8NG12QJd+9nAAAAJwAAAARAAAAAAAAAAAAAACAAZMAAAB3b3JkL2RvY3VtZW50LnhtbFBLAQIUABQAAAAAAE8NG13gh3YLCAIAAAgCAAARAAAAAAAAAAAAAACAAV4BAABkb2NQcm9wcy9jb3JlLnhtbFBLAQIUABQAAAAAAE8NG10URxZ58AAAAPAAAAAQAAAAAAAAAAAAAACAAZUDAABkb2NQcm9wcy9hcHAueG1sUEsBAhQAFAAAAAAATw0bXVmFdE11AQAAdQEAABMAAAAAAAAAAAAAAIABswQAAGRvY1Byb3BzL2N1c3RvbS54bWxQSwUGAAAAAAUABQA+AQAAWQYAAAAA";

/// A full analysis over a marked document file reports the mark and the format.
#[test]
fn file_analyze_reports_on_a_marked_file() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let report = session.run(
        "file_analyze",
        json!({ "file_base64": B64.encode(file_marked().as_bytes()), "format": "txt" }),
    );
    assert_eq!(report["format"], json!("text"));
    // The report is the whole forensic report, verdict and invisible breakdown
    // included, not a summary.
    assert!(report.get("verdict").is_some(), "the report must carry a verdict");
    let invisible = report["unicode_analysis"]["invisible_breakdown"]
        .as_object()
        .expect("the analysis reports an invisible breakdown");
    assert!(
        !invisible.is_empty(),
        "a marked file must report invisible characters"
    );
}

/// Concealing into a text file returns base64 that decodes to a marked file
/// which re-inspects as marked over the surface.
#[test]
fn file_conceal_returns_a_marked_file_that_reinspects_marked() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let cover = conceal_cover();
    let result = session.run(
        "file_conceal",
        json!({ "file_base64": B64.encode(cover.as_bytes()), "format": "txt", "secret": "hi" }),
    );
    assert_eq!(result["format"], json!("text"));
    assert_eq!(result["round_trip"]["verified"], json!(true));
    assert_eq!(result["secret_bytes"], json!(2));

    // The marked bytes really differ from the cover: a real placement.
    let marked_b64 = result["marked_file_base64"].as_str().unwrap();
    assert_ne!(
        B64.decode(marked_b64).unwrap(),
        cover.as_bytes(),
        "the conceal must alter the document"
    );

    // Re-inspecting the returned file over the surface reports the zero-width class.
    let report = session.run(
        "file_inspect",
        json!({ "file_base64": marked_b64, "format": "txt" }),
    );
    let zw = report["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!("zero_width"))
        .expect("zero_width class listed");
    assert!(zw["count"].as_u64().unwrap() > 0);
}

/// Concealing into a container (DOCX) is refused by name, never faked.
#[test]
fn file_conceal_refuses_a_container_by_name() {
    let mut session = Session::open();

    let (code, reason) = session.refuse(
        "file_conceal",
        json!({ "file_base64": FIXTURE_DOCX_B64, "format": "docx", "secret": "hi" }),
    );
    assert_eq!(code, "file_conceal_refused");
    assert!(
        reason.contains("DOCX"),
        "the refusal must name the container format: {reason}"
    );
}

/// Converting Markdown to HTML returns base64 that carries the rendered heading,
/// and the result is declared lossy.
#[test]
fn file_convert_md_to_html_contains_a_heading() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let result = session.run(
        "file_convert",
        json!({ "file_base64": B64.encode(b"# Title\n\nBody text.\n"), "format": "md", "target": "html" }),
    );
    assert_eq!(result["source_format"], json!("markdown"));
    assert_eq!(result["target_format"], json!("html"));
    assert_eq!(result["lossy"], json!(true));

    let html = String::from_utf8(
        B64.decode(result["converted_file_base64"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(
        html.contains("<h1>Title</h1>"),
        "the converted HTML must carry the heading: {html}"
    );
}

/// Converting to a target this build cannot write is refused by name.
#[test]
fn file_convert_refuses_an_unsupported_target_by_name() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let (code, reason) = session.refuse(
        "file_convert",
        json!({ "file_base64": B64.encode(b"# Title\n"), "format": "md", "target": "docx" }),
    );
    assert_eq!(code, "file_convert_unsupported_target");
    assert!(
        reason.contains("docx"),
        "the refusal must name the unsupported target: {reason}"
    );
}

/// Reading a DOCX's metadata returns its docProps over the surface.
#[test]
fn file_metadata_reads_docx_docprops() {
    let mut session = Session::open();

    let report = session.run(
        "file_metadata",
        json!({ "file_base64": FIXTURE_DOCX_B64, "format": "docx" }),
    );
    assert_eq!(report["format"], json!("docx"));
    assert_eq!(report["kind"], json!("document"));
    assert_eq!(
        report["native_metadata"]["title"],
        json!("Quarterly Report")
    );
    assert_eq!(report["native_metadata"]["creator"], json!("Ada Lovelace"));
    // The DOCX carries no added channel, reported explicitly rather than omitted.
    assert_eq!(report["embedded_channel"]["present"], json!(false));
}

/// A format that carries no metadata this tool reads is refused by name.
#[test]
fn file_metadata_refuses_a_no_metadata_format_by_name() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let mut session = Session::open();

    let (code, reason) = session.refuse(
        "file_metadata",
        json!({ "file_base64": B64.encode(b"# Title\n"), "format": "md" }),
    );
    assert_eq!(code, "file_metadata_unsupported");
    assert!(
        reason.contains("markdown"),
        "the refusal must name the format: {reason}"
    );
}
