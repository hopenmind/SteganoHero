//! Integration tests for the AI-regulation tool over the real binary: the
//! document sovereignty subcommands (inspect and clean) driven over a corpus
//! document, and the C2PA reader driven over the genuine AR-2 fixtures.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

fn corpus(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("corpus")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("corpus document {} is missing: {e}", path.display()))
}

fn c2pa_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stegano-core")
        .join("tests")
        .join("fixtures")
        .join("c2pa")
        .join(name)
}

/// Inspect reports the marks a document carries, by class and count, as JSON.
#[test]
fn document_inspect_reports_marks_as_json() {
    let doc = corpus("already_carrying.txt");

    let output = stegano_bin()
        .args(["document", "inspect", "--document", &doc, "--format", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "document inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("inspect must emit JSON");
    let count = |id: &str| {
        report["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap()["count"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(count("zero_width"), 2);
    assert_eq!(count("whitespace_var"), 2);
    assert_eq!(count("homoglyph"), 0);
}

/// Clean removes the chosen class, leaves the rest, and always reports the
/// honest residual note.
#[test]
fn document_clean_removes_a_chosen_class_and_reports_residual() {
    let doc = corpus("already_carrying.txt");

    let output = stegano_bin()
        .args([
            "document", "clean", "--document", &doc, "--class", "zero_width", "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "document clean failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("clean must emit JSON");
    assert_eq!(report["altered"], json!(true));
    let removed = report["removed"].as_array().unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["id"], json!("zero_width"));
    assert_eq!(removed[0]["count"], json!(2));
    assert!(report["residual"].as_array().unwrap().len() >= 3);

    let text = report["cleaned_text"].as_str().unwrap();
    assert!(!text.contains('\u{200B}') && !text.contains('\u{200C}'));
    assert!(text.contains('\u{2060}') && text.contains('\u{FEFF}'));
}

/// A file with no content credential is reported Absent, not raised as an error.
#[test]
fn c2pa_inspect_reports_absent_on_a_file_without_a_credential() {
    let file = c2pa_fixture("no_manifest.png");

    let output = stegano_bin()
        .args([
            "c2pa",
            "inspect",
            "--file",
            file.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "c2pa inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("c2pa inspect must emit JSON");
    assert_eq!(report["present"], json!(false));
    assert_eq!(report["verdict"], json!("absent"));
    assert!(report["manifest"].is_null());
}

/// The verdict mirrors the reader's validation state on a genuine signed file
/// and never overstates trust: intact signature, trust anchor not established.
#[test]
fn c2pa_inspect_mirrors_the_readers_verdict_on_a_signed_file() {
    let file = c2pa_fixture("genuine_signed.jpg");

    let output = stegano_bin()
        .args([
            "c2pa",
            "inspect",
            "--file",
            file.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "c2pa inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("c2pa inspect must emit JSON");
    assert_eq!(report["present"], json!(true));
    assert_eq!(report["verdict"], json!("signature_valid"));
    assert_eq!(report["trust_anchor_established"], json!(false));
}
