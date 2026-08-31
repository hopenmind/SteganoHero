//! Integration tests for the `file` subcommands (analyse, conceal, convert,
//! metadata) driven over real FILEs through the actual binary. Fixtures are a
//! generous cover the concealment ceiling admits, a Markdown source with a
//! heading, and an embedded minimal DOCX carrying known docProps, so nothing is
//! guessed and no zip dependency is needed here.

use std::process::Command;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

fn stegano_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegano"))
}

/// A cover generous enough for the concealment density ceiling to admit a small
/// secret. The file conceal runs under the Conceal mission, like the desktop, so
/// a short cover offers no room; this repeated sentence gives the carrier slack.
fn conceal_cover() -> String {
    "Every record in the ledger is kept legible for the whole review team. ".repeat(80)
}

/// A minimal but valid DOCX carrying known docProps (title, creator, keywords, a
/// custom property), base64 encoded and embedded so the test needs no zip crate.
const FIXTURE_DOCX_B64: &str = "UEsDBBQAAAAAAE8NG13muHRrYgAAAGIAAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbDw/eG1sIHZlcnNpb249IjEuMCI/PjxUeXBlcyB4bWxucz0iaHR0cDovL3NjaGVtYXMub3BlbnhtbGZvcm1hdHMub3JnL3BhY2thZ2UvMjAwNi9jb250ZW50LXR5cGVzIi8+UEsDBBQAAAAAAE8NG12QJd+9nAAAAJwAAAARAAAAd29yZC9kb2N1bWVudC54bWw8dzpkb2N1bWVudCB4bWxuczp3PSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvd29yZHByb2Nlc3NpbmdtbC8yMDA2L21haW4iPjx3OmJvZHk+PHc6cD48dzpyPjx3OnQ+Qm9keSB0ZXh0Ljwvdzp0PjwvdzpyPjwvdzpwPjwvdzpib2R5Pjwvdzpkb2N1bWVudD5QSwMEFAAAAAAATw0bXeCHdgsIAgAACAIAABEAAABkb2NQcm9wcy9jb3JlLnhtbDw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz48Y3A6Y29yZVByb3BlcnRpZXMgeG1sbnM6Y3A9Imh0dHA6Ly9zY2hlbWFzLm9wZW54bWxmb3JtYXRzLm9yZy9wYWNrYWdlLzIwMDYvbWV0YWRhdGEvY29yZS1wcm9wZXJ0aWVzIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOmRjdGVybXM9Imh0dHA6Ly9wdXJsLm9yZy9kYy90ZXJtcy8iIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiPjxkYzp0aXRsZT5RdWFydGVybHkgUmVwb3J0PC9kYzp0aXRsZT48ZGM6Y3JlYXRvcj5BZGEgTG92ZWxhY2U8L2RjOmNyZWF0b3I+PGNwOmtleXdvcmRzPmZpbmFuY2UsIHEzLCBpbnRlcm5hbDwvY3A6a2V5d29yZHM+PGRjdGVybXM6Y3JlYXRlZCB4c2k6dHlwZT0iZGN0ZXJtczpXM0NEVEYiPjIwMjYtMDEtMDJUMDk6MDA6MDBaPC9kY3Rlcm1zOmNyZWF0ZWQ+PC9jcDpjb3JlUHJvcGVydGllcz5QSwMEFAAAAAAATw0bXRRHFnnwAAAA8AAAABAAAABkb2NQcm9wcy9hcHAueG1sPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/PjxQcm9wZXJ0aWVzIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvb2ZmaWNlRG9jdW1lbnQvMjAwNi9leHRlbmRlZC1wcm9wZXJ0aWVzIj48QXBwbGljYXRpb24+TWljcm9zb2Z0IE9mZmljZSBXb3JkPC9BcHBsaWNhdGlvbj48Q29tcGFueT5Ib3BlIG4gTWluZDwvQ29tcGFueT48L1Byb3BlcnRpZXM+UEsDBBQAAAAAAE8NG11ZhXRNdQEAAHUBAAATAAAAZG9jUHJvcHMvY3VzdG9tLnhtbDw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz48UHJvcGVydGllcyB4bWxucz0iaHR0cDovL3NjaGVtYXMub3BlbnhtbGZvcm1hdHMub3JnL29mZmljZURvY3VtZW50LzIwMDYvY3VzdG9tLXByb3BlcnRpZXMiIHhtbG5zOnZ0PSJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvb2ZmaWNlRG9jdW1lbnQvMjAwNi9kb2NQcm9wc1ZUeXBlcyI+PHByb3BlcnR5IGZtdGlkPSJ7RDVDREQ1MDUtMkU5Qy0xMDFCLTkzOTctMDgwMDJCMkNGOUFFfSIgcGlkPSIyIiBuYW1lPSJDbGFzc2lmaWNhdGlvbiI+PHZ0Omxwd3N0cj5Db25maWRlbnRpYWw8L3Z0Omxwd3N0cj48L3Byb3BlcnR5PjwvUHJvcGVydGllcz5QSwECFAAUAAAAAABPDRtd5rh0a2IAAABiAAAAEwAAAAAAAAAAAAAAgAEAAAAAW0NvbnRlbnRfVHlwZXNdLnhtbFBLAQIUABQAAAAAAE8NG12QJd+9nAAAAJwAAAARAAAAAAAAAAAAAACAAZMAAAB3b3JkL2RvY3VtZW50LnhtbFBLAQIUABQAAAAAAE8NG13gh3YLCAIAAAgCAAARAAAAAAAAAAAAAACAAV4BAABkb2NQcm9wcy9jb3JlLnhtbFBLAQIUABQAAAAAAE8NG10URxZ58AAAAPAAAAAQAAAAAAAAAAAAAACAAZUDAABkb2NQcm9wcy9hcHAueG1sUEsBAhQAFAAAAAAATw0bXVmFdE11AQAAdQEAABMAAAAAAAAAAAAAAIABswQAAGRvY1Byb3BzL2N1c3RvbS54bWxQSwUGAAAAAAUABQA+AQAAWQYAAAAA";

/// `file conceal --file --output` marks a text file, and a fresh `file analyze`
/// of the written file reports the mark.
#[test]
fn file_conceal_then_analyze_reports_the_mark() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.txt");
    let marked = dir.path().join("marked.txt");
    std::fs::write(&cover, conceal_cover()).unwrap();

    let out = stegano_bin()
        .args([
            "file", "conceal", "--file", cover.to_str().unwrap(), "--secret", "hi", "--output",
            marked.to_str().unwrap(), "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "file conceal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("conceal must emit JSON");
    assert_eq!(report["format"], json!("text"));
    assert_eq!(report["round_trip"]["verified"], json!(true));
    assert_eq!(report["written_in_place"], json!(false));

    // The marked file differs from the cover: a real placement, not the input.
    assert_ne!(std::fs::read(&marked).unwrap(), conceal_cover().into_bytes());

    // A fresh analysis of the written file reports the invisible characters.
    let analyze = stegano_bin()
        .args(["file", "analyze", "--file", marked.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(
        analyze.status.success(),
        "file analyze failed: {}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    let report: Value = serde_json::from_slice(&analyze.stdout).expect("analyze must emit JSON");
    let invisible = report["unicode_analysis"]["invisible_breakdown"]
        .as_object()
        .expect("the analysis reports an invisible breakdown");
    assert!(
        !invisible.is_empty(),
        "the marked file must report invisible characters"
    );
}

/// Concealing into a container (DOCX) is refused by name and exits non-zero.
#[test]
fn file_conceal_refuses_a_container_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let docx = dir.path().join("fixture.docx");
    std::fs::write(&docx, B64.decode(FIXTURE_DOCX_B64).unwrap()).unwrap();

    let out = stegano_bin()
        .args(["file", "conceal", "--file", docx.to_str().unwrap(), "--secret", "hi"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a container conceal must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DOCX"),
        "the refusal must name the container format: {stderr}"
    );
}

/// `file convert --target html` renders a heading to <h1>; the report is lossy.
#[test]
fn file_convert_md_to_html_contains_a_heading() {
    let dir = tempfile::tempdir().unwrap();
    let md = dir.path().join("doc.md");
    let html = dir.path().join("doc.html");
    std::fs::write(&md, "# Title\n\nBody text.\n").unwrap();

    let out = stegano_bin()
        .args([
            "file", "convert", "--file", md.to_str().unwrap(), "--target", "html", "--output",
            html.to_str().unwrap(), "--format", "json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "file convert failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("convert must emit JSON");
    assert_eq!(report["target_format"], json!("html"));
    assert_eq!(report["lossy"], json!(true));

    let produced = std::fs::read_to_string(&html).unwrap();
    assert!(
        produced.contains("<h1>Title</h1>"),
        "the converted HTML must carry the heading: {produced}"
    );
}

/// Converting to a target this build cannot write is refused by name.
#[test]
fn file_convert_refuses_an_unsupported_target_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let md = dir.path().join("doc.md");
    let out_path = dir.path().join("out.docx");
    std::fs::write(&md, "# Title\n").unwrap();

    let out = stegano_bin()
        .args([
            "file", "convert", "--file", md.to_str().unwrap(), "--target", "docx", "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "an unsupported target must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("docx"),
        "the refusal must name the unsupported target: {stderr}"
    );
}

/// `file metadata --file` reads a DOCX's docProps.
#[test]
fn file_metadata_reads_docx_docprops() {
    let dir = tempfile::tempdir().unwrap();
    let docx = dir.path().join("fixture.docx");
    std::fs::write(&docx, B64.decode(FIXTURE_DOCX_B64).unwrap()).unwrap();

    let out = stegano_bin()
        .args(["file", "metadata", "--file", docx.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "file metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).expect("metadata must emit JSON");
    assert_eq!(report["format"], json!("docx"));
    assert_eq!(report["kind"], json!("document"));
    assert_eq!(report["native_metadata"]["title"], json!("Quarterly Report"));
    assert_eq!(report["native_metadata"]["creator"], json!("Ada Lovelace"));
    assert_eq!(report["embedded_channel"]["present"], json!(false));
}

/// A format with no metadata this tool reads is refused by name and exits non-zero.
#[test]
fn file_metadata_refuses_a_no_metadata_format_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let md = dir.path().join("doc.md");
    std::fs::write(&md, "# Title\n").unwrap();

    let out = stegano_bin()
        .args(["file", "metadata", "--file", md.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a no-metadata format must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("markdown"),
        "the refusal must name the format: {stderr}"
    );
}
