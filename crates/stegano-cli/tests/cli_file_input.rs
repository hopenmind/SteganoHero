//! Integration tests for uniform file input on the text-reading commands: decode,
//! detect, forensic and capacity now accept a document file in place of pasted
//! text, driven over the real binary.

use std::process::Command;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

/// A cover generous enough for the default carrier to admit a small secret.
fn cover() -> String {
    "Every line of the report stays legible to the whole review team. ".repeat(40)
}

#[test]
fn a_marked_text_file_is_decoded_from_the_file() {
    // Hide a secret in a cover, save the marked text as a .txt file, then read it
    // back with decode --file: the CLI counterpart of the API's uniform file input.
    let dir = tempfile::tempdir().unwrap();
    let secret = "meet at the west gate";

    let encoded = stegano_bin()
        .args(["encode", "--cover", &cover(), "--secret", secret])
        .output()
        .unwrap();
    assert!(encoded.status.success(), "encode failed: {}", String::from_utf8_lossy(&encoded.stderr));
    let stego = String::from_utf8(encoded.stdout).unwrap();
    let stego = stego.trim_end_matches('\n');

    let path = dir.path().join("marked.txt");
    std::fs::write(&path, stego).unwrap();

    let decoded = stegano_bin()
        .args(["decode", "--file", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(decoded.status.success(), "decode --file failed: {}", String::from_utf8_lossy(&decoded.stderr));
    let recovered = String::from_utf8(decoded.stdout).unwrap();
    assert_eq!(recovered.trim_end_matches('\n'), secret, "the secret is read back from the file");
}

#[test]
fn canary_generate_runs_on_a_document_file() {
    // The traceability generator watermarks a document read from a file, the same
    // uniform file input the read commands accept.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("brief.md");
    std::fs::write(&path, "# Brief\n\nThe quarterly figures for the review team.").unwrap();

    let out = stegano_bin()
        .args([
            "canary", "generate",
            "--file", path.to_str().unwrap(),
            "--recipients", "alice,bob",
            "--salt", "unique-salt-value",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "canary generate --file failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!out.stdout.is_empty(), "watermarked versions were produced from the file");
}

#[test]
fn forensic_runs_on_a_document_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("note.md");
    std::fs::write(&path, "# Note\n\nnothing hidden here").unwrap();

    let out = stegano_bin()
        .args(["forensic", "--file", path.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "forensic --file failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!out.stdout.is_empty(), "a report was produced over the file's text");
}

#[test]
fn supplying_both_text_and_file_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.txt");
    std::fs::write(&path, "content").unwrap();

    let out = stegano_bin()
        .args(["detect", "--text", "inline", "--file", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "double supply must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not both"), "names the conflict: {err}");
}

#[test]
fn supplying_neither_text_nor_file_is_refused_by_name() {
    let out = stegano_bin().args(["detect"]).output().unwrap();
    assert!(!out.status.success(), "missing subject must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--text or --file"), "names what to supply: {err}");
}

#[test]
fn export_writes_a_result_to_a_file_byte_faithfully() {
    // A marked text exported to txt must be byte-identical, so its hidden layer
    // survives the export.
    let dir = tempfile::tempdir().unwrap();
    let secret = "the ledger is clean";
    let encoded = stegano_bin()
        .args(["encode", "--cover", &cover(), "--secret", secret])
        .output()
        .unwrap();
    let stego = String::from_utf8(encoded.stdout).unwrap();
    let stego = stego.trim_end_matches('\n');

    let out_path = dir.path().join("result.txt");
    let exported = stegano_bin()
        .args(["export", "--text", stego, "--to", "txt", "--output", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(exported.status.success(), "export failed: {}", String::from_utf8_lossy(&exported.stderr));
    let written = std::fs::read_to_string(&out_path).unwrap();
    assert_eq!(written, stego, "txt export is byte-faithful");

    // And the marked file still decodes, proving the hidden layer survived export.
    let decoded = stegano_bin()
        .args(["decode", "--file", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(decoded.stdout).unwrap().trim_end_matches('\n'), secret);
}

#[test]
fn export_to_html_produces_a_document() {
    let out = stegano_bin()
        .args(["export", "--text", "a finding worth keeping", "--to", "html"])
        .output()
        .unwrap();
    assert!(out.status.success(), "html export failed: {}", String::from_utf8_lossy(&out.stderr));
    let html = String::from_utf8(out.stdout).unwrap();
    assert!(html.contains("finding worth keeping"), "the html carries the content");
}

#[test]
fn export_to_pdf_produces_a_native_pdf_file() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("report.pdf");
    let out = stegano_bin()
        .args(["export", "--text", "a short report", "--to", "pdf", "--output", out_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "pdf export failed: {}", String::from_utf8_lossy(&out.stderr));
    let bytes = std::fs::read(&out_path).unwrap();
    assert!(bytes.starts_with(b"%PDF"), "a PDF file was written");
}

#[test]
fn export_to_an_unknown_target_is_refused_by_name() {
    let out = stegano_bin()
        .args(["export", "--text", "x", "--to", "xyz"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "an unknown target must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown export target"), "names the target: {err}");
}
