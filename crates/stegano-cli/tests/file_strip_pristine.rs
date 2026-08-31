//! Integration tests for the `file strip` and `file pristine` subcommands driven
//! over a real FILE through the actual binary. Strip removes metadata with the
//! content byte-identical; pristine removes every mark class AND every remaining
//! invisible from a text file and names its trade-off.

use std::process::Command;

use serde_json::Value;

use stegano_core::stego::ZeroWidth;
use stegano_core::traits::StegoMethod;

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

fn png_chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(12 + data.len());
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(ctype);
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(&[0, 0, 0, 0]); // placeholder CRC; strip copies verbatim
    chunk
}

fn png_with_metadata() -> (Vec<u8>, Vec<u8>) {
    let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]; // 1x1, 8-bit RGB
    let idat = [9u8, 8, 7, 6, 5, 4, 3, 2];
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&png_chunk(b"tEXt", b"steganohero\0payload"));
    png.extend_from_slice(&png_chunk(b"IDAT", &idat));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));
    (png, png_chunk(b"IDAT", &idat))
}

/// `file strip --file <png>` removes the metadata chunk with the pixels intact.
#[test]
fn file_strip_removes_metadata_and_keeps_content() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("marked.png");
    let out = dir.path().join("clean.png");
    let (png, idat_chunk) = png_with_metadata();
    std::fs::write(&src, &png).unwrap();

    let output = stegano_bin()
        .args([
            "file", "strip", "--file", src.to_str().unwrap(),
            "--output", out.to_str().unwrap(), "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "file strip failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("strip must emit JSON");
    assert_eq!(report["altered"], Value::Bool(true));
    assert_eq!(report["content_identical"], Value::Bool(true));

    let stripped = std::fs::read(&out).unwrap();
    assert!(
        !stripped.windows(4).any(|w| w == b"tEXt"),
        "the metadata chunk is removed from the written file"
    );
    assert!(
        stripped.windows(idat_chunk.len()).any(|w| w == idat_chunk.as_slice()),
        "the IDAT (pixel) chunk survives byte-identical"
    );
}

/// `file strip` on a text file with no metadata surface is refused by name.
#[test]
fn file_strip_on_a_text_file_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("note.md");
    std::fs::write(&src, "# Title\n\nJust text.\n").unwrap();

    let output = stegano_bin()
        .args(["file", "strip", "--file", src.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "a text file has no metadata to strip");
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("[error]"), "the refusal is named on stderr: {err}");
}

/// `file pristine --file <md>` removes the mark and the orphan invisibles and
/// names the trade-off.
#[test]
fn file_pristine_removes_marks_and_invisibles_and_names_the_tradeoff() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("marked.md");

    // A real zero-width mark from the core carrier, plus an orphan soft hyphen and
    // an invisible separator that no mark class owns.
    let cover = "The quick brown fox jumps over the lazy dog near the bank";
    let marked = ZeroWidth::new().encode(cover, b"x").unwrap();
    assert_ne!(marked, cover, "the fixture must actually carry a mark");
    let dirty = format!("{marked}\u{00AD}\u{2063}");
    std::fs::write(&src, &dirty).unwrap();

    let output = stegano_bin()
        .args([
            "file", "pristine", "--file", src.to_str().unwrap(), "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "file pristine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("pristine must emit JSON");
    assert_eq!(report["altered"], Value::Bool(true));
    assert!(
        report["invisibles_removed"].as_u64().unwrap() >= 1,
        "the orphan invisibles were counted"
    );
    assert!(
        !report["notes"].as_array().unwrap().is_empty(),
        "the meaning-bearing trade-off is named"
    );

    // The written file re-analyses with no invisible characters left.
    let cleaned = std::fs::read_to_string(&src).unwrap();
    assert!(
        !cleaned.chars().any(|c| matches!(c as u32,
            0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069
            | 0xFEFF | 0x00AD | 0x034F | 0x061C | 0x180E)),
        "no invisible or format-control character remains: {cleaned:?}"
    );
}

/// `file pristine` on a container is refused by name.
#[test]
fn file_pristine_on_a_container_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("doc.docx");
    // A non-DOCX payload under a .docx name: extraction fails and the refusal is
    // named, never a silent pass.
    std::fs::write(&src, b"not a real docx").unwrap();

    let output = stegano_bin()
        .args(["file", "pristine", "--file", src.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "container pristine is refused");
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("[error]"), "the refusal is named on stderr: {err}");
}
