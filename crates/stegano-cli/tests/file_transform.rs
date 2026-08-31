//! Integration tests for the document inspect/clean subcommands driven over a
//! real FILE (`--file <path>`), through the actual binary. The fixture is a
//! plain-text document provably marked with the core's own zero-width carrier,
//! so the mark is real rather than a guessed code point.

use std::process::Command;

use serde_json::{json, Value};

use stegano_core::stego::ZeroWidth;
use stegano_core::traits::StegoMethod;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

/// A cover long enough for the zero-width carrier to place a byte of payload.
const COVER: &str = "The quick brown fox jumps over the lazy dog near the bank";

/// `COVER` marked with a real zero-width payload the core carrier placed.
fn marked() -> String {
    let marked = ZeroWidth::new().encode(COVER, b"x").unwrap();
    assert_ne!(marked, COVER, "the fixture must actually carry a mark");
    marked
}

/// `document inspect --file <marked file>` reports the zero-width class.
#[test]
fn document_inspect_file_reports_the_class() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marked.txt");
    std::fs::write(&path, marked()).unwrap();

    let output = stegano_bin()
        .args([
            "document", "inspect", "--file", path.to_str().unwrap(), "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "document inspect --file failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("inspect must emit JSON");
    let zw = report["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!("zero_width"))
        .expect("zero_width class listed");
    assert!(
        zw["count"].as_u64().unwrap() > 0,
        "the marked file must report zero-width marks"
    );
}

/// `document clean --file` strips the class in place, and the written file
/// re-inspects clean.
#[test]
fn document_clean_file_in_place_strips_and_reinspects_clean() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marked.txt");
    std::fs::write(&path, marked()).unwrap();

    let output = stegano_bin()
        .args([
            "document", "clean", "--file", path.to_str().unwrap(), "--class", "zero_width",
            "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "document clean --file failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("clean must emit JSON");
    assert_eq!(report["altered"], json!(true));
    assert_eq!(report["written_in_place"], json!(true));
    let removed = report["removed"].as_array().unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["id"], json!("zero_width"));
    assert!(removed[0]["count"].as_u64().unwrap() > 0);
    // The honest residual note is always present.
    assert!(report["residual"].as_array().unwrap().len() >= 3);

    // The written file no longer carries the mark: it is the cover again.
    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(written, COVER);

    // Proven over the surface too: a fresh inspect of the written file is clean.
    let recheck = stegano_bin()
        .args(["document", "inspect", "--file", path.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(recheck.status.success());
    let rechecked: Value = serde_json::from_slice(&recheck.stdout).unwrap();
    let zw = rechecked["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!("zero_width"))
        .unwrap();
    assert_eq!(zw["count"], json!(0));
}

/// `--output` writes the cleaned document to a new file and leaves the source
/// untouched.
#[test]
fn document_clean_file_to_output_leaves_the_source_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("marked.txt");
    let dst = dir.path().join("cleaned.txt");
    let marked_text = marked();
    std::fs::write(&src, &marked_text).unwrap();

    let output = stegano_bin()
        .args([
            "document", "clean", "--file", src.to_str().unwrap(), "--output",
            dst.to_str().unwrap(), "--class", "zero_width", "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "document clean --file --output failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["written_in_place"], json!(false));

    // The source is byte-for-byte what it was; the destination is cleaned.
    assert_eq!(std::fs::read_to_string(&src).unwrap(), marked_text);
    assert_eq!(std::fs::read_to_string(&dst).unwrap(), COVER);
}

/// An unknown format is a named refusal and a non-zero exit.
#[test]
fn document_inspect_file_refuses_an_unknown_format_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mystery.pdf");
    std::fs::write(&path, b"%PDF-1.4 not really a pdf").unwrap();

    let output = stegano_bin()
        .args(["document", "inspect", "--file", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "an unknown format must refuse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("unsupported") && stderr.contains("pdf"),
        "the refusal must name the unsupported format: {stderr}"
    );
}

/// Cleaning an HTML document is a named refusal (a lossless text-node rewrite of
/// arbitrary HTML is out of reach this build), and a non-zero exit.
#[test]
fn document_clean_file_refuses_html_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("page.html");
    std::fs::write(&path, b"<html><body><p>Body with a mark.</p></body></html>").unwrap();

    let output = stegano_bin()
        .args(["document", "clean", "--file", path.to_str().unwrap(), "--class", "zero_width"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "HTML clean must refuse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("HTML"),
        "the refusal must name the HTML format: {stderr}"
    );
}
