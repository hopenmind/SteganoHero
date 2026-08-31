//! Integration test: the provenance CLI, driven over the real binary.
//!
//! keygen -> sign -> verify (holds) -> tamper (fails by name), for the detached
//! and in-band bindings, plus the named capacity refusal.

use std::process::Command;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

/// A cover long enough to hold a full signed claim through a bounded carrier.
const COVER: &str = "Access to the open science project expectations are exceptional in scope \
and practice today across every possible aspect of the ecosystem operations including all \
cooperative joint exercises previously associated with the core operations executive committee \
since its inception a full year ago today across the divisions and their many shared programmes.";

/// keygen with JSON output yields a usable base64 key pair.
fn keypair() -> (String, String) {
    let output = stegano_bin()
        .args(["provenance", "keygen", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let keys: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
    (
        keys["private_key_base64"].as_str().unwrap().to_string(),
        keys["public_key_base64"].as_str().unwrap().to_string(),
    )
}

#[test]
fn provenance_detached_sign_verify_and_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = keypair();

    // Sign a detached record asserting human authorship.
    let signed = stegano_bin()
        .args([
            "provenance", "sign",
            "--cover", COVER,
            "--human",
            "--author", "Hope n Mind",
            "--private-key", &private,
        ])
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );

    // The sidecar is JSON, and it never carries the private key.
    let sidecar_text = String::from_utf8(signed.stdout).unwrap();
    let _: serde_json::Value = serde_json::from_str(sidecar_text.trim()).unwrap();
    assert!(!sidecar_text.contains(&private), "the private key leaked into the sidecar");

    let sidecar_path = dir.path().join("record.json");
    std::fs::write(&sidecar_path, sidecar_text.trim()).unwrap();

    // Verify: it holds.
    let verified = stegano_bin()
        .args([
            "provenance", "verify",
            "--document", COVER,
            "--sidecar-file", sidecar_path.to_str().unwrap(),
            "--trusted-key", &public,
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "verify should hold, stdout: {}",
        String::from_utf8_lossy(&verified.stdout)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("HOLDS"));

    // Tamper the document: verification fails by name.
    let edited = format!("{COVER} One more sentence, added by somebody else.");
    let tampered = stegano_bin()
        .args([
            "provenance", "verify",
            "--document", &edited,
            "--sidecar-file", sidecar_path.to_str().unwrap(),
            "--trusted-key", &public,
        ])
        .output()
        .unwrap();
    assert!(
        !tampered.status.success(),
        "verify must fail on a tampered document"
    );
    let out = String::from_utf8_lossy(&tampered.stdout);
    assert!(
        out.contains("ALTERED") || out.to_lowercase().contains("altered"),
        "the failure must name the alteration, stdout was: {out}"
    );
}

#[test]
fn provenance_in_band_sign_and_verify() {
    let (private, public) = keypair();

    // Sign an AI-generated disclosure carried within the document itself.
    let signed = stegano_bin()
        .args([
            "provenance", "sign",
            "--cover", COVER,
            "--ai",
            "--model", "assistant",
            "--provider", "lab",
            "--binding", "in_band",
            "--carrier", "zero_width",
            "--private-key", &private,
        ])
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "in-band sign failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let marked = String::from_utf8(signed.stdout).unwrap();
    let marked = marked.trim_end_matches('\n');

    // Verify the in-band record, naming the carrier to read it from.
    let verified = stegano_bin()
        .args([
            "provenance", "verify",
            "--document", marked,
            "--trusted-key", &public,
            "--carrier", "zero_width",
            "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "in-band verify should hold, stdout: {}",
        String::from_utf8_lossy(&verified.stdout)
    );
    let report: serde_json::Value =
        serde_json::from_str(String::from_utf8(verified.stdout).unwrap().trim()).unwrap();
    assert_eq!(report["claims"][0]["binding"], serde_json::json!("in_band"));
    assert_eq!(
        report["claims"][0]["signature_valid"],
        serde_json::json!(true)
    );
}

#[test]
fn provenance_in_band_too_small_document_is_refused_by_name() {
    let (private, _public) = keypair();

    let signed = stegano_bin()
        .args([
            "provenance", "sign",
            "--cover", "ok thanks",
            "--human",
            "--binding", "in_band",
            "--carrier", "homoglyph",
            "--private-key", &private,
        ])
        .output()
        .unwrap();
    assert!(
        !signed.status.success(),
        "a document too small for an in-band record must be refused"
    );
    let err = String::from_utf8_lossy(&signed.stderr);
    assert!(err.contains("bits"), "the refusal must name the arithmetic: {err}");
}
