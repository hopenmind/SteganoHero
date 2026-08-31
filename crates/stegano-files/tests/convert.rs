//! Format-to-format conversion (Phase C): DECLARED LOSSY, SEPARATE FROM MARKING.
//!
//! Each working target has a test that converts a small Markdown source (a
//! heading, a bold run, a list) and asserts a characteristic marker of the target
//! is present. Plus the raise-by-name refusals: an unsupported target (a
//! Typst-linked container) and an unextractable source (an image format). The
//! math tests prove the declared-lossy passthrough carries LaTeX as source rather
//! than corrupting it or dropping it silently (invariant 2).

use stegano_files::{convert_file, supported_targets, ConvertError, FileFormat};

/// A small Markdown source exercising a heading, a bold run, and a list.
const SRC: &str = "# Title\n\nSome **bold** text.\n\n- one\n- two\n";

fn convert(target: FileFormat) -> String {
    let out = convert_file(SRC.as_bytes(), FileFormat::Markdown, target)
        .unwrap_or_else(|e| panic!("convert to {target:?} failed: {e}"));
    String::from_utf8(out).expect("target bytes are valid UTF-8")
}

// ── The supported-target set ─────────────────────────────────────────────────

#[test]
fn supported_targets_are_the_ten_pure_rust_writers() {
    let targets = supported_targets();
    assert_eq!(targets.len(), 10, "unexpected target set: {targets:?}");
    for expected in [
        FileFormat::Markdown,
        FileFormat::Html,
        FileFormat::PlainText,
        FileFormat::Latex,
        FileFormat::Rtf,
        FileFormat::Org,
        FileFormat::Rst,
        FileFormat::AsciiDoc,
        FileFormat::Ipynb,
        FileFormat::Typst,
    ] {
        assert!(targets.contains(&expected), "missing target {expected:?}");
    }
    // The Typst-linked containers are NOT supported targets in this build.
    assert!(!targets.contains(&FileFormat::Docx));
    assert!(!targets.contains(&FileFormat::Odt));
    assert!(!targets.contains(&FileFormat::Epub));
    // PDF is a conversion target too, but browser-backed (Phase D1), NOT a pure-Rust
    // writer: it is handled distinctly and is deliberately absent from this list.
    assert!(!targets.contains(&FileFormat::Pdf));
    assert!(!stegano_files::is_supported_target(FileFormat::Pdf));
}

// ── Per-target characteristic markers ────────────────────────────────────────

#[test]
fn markdown_target_is_the_waypoint_re_emitted() {
    // The Markdown target re-emits the waypoint unchanged: identity for a Markdown
    // source (no round-trip loss for this one target).
    let out = convert(FileFormat::Markdown);
    assert_eq!(out, SRC);
}

#[test]
fn html_target_has_h1_and_strong_and_list() {
    let out = convert(FileFormat::Html);
    assert!(out.contains("<h1>Title</h1>"), "no <h1>: {out}");
    assert!(out.contains("<strong>bold</strong>"), "no <strong>: {out}");
    assert!(out.contains("<li>one</li>"), "no <li>: {out}");
    assert!(out.contains("<!DOCTYPE html>"), "no doctype: {out}");
}

#[test]
fn plaintext_target_has_heading_and_bullet() {
    let out = convert(FileFormat::PlainText);
    assert!(out.contains("Title"), "heading text lost: {out}");
    assert!(out.contains('\u{2022}'), "no bullet: {out}");
    assert!(out.contains("one") && out.contains("two"), "list items lost: {out}");
}

#[test]
fn tex_target_has_section_and_textbf() {
    let out = convert(FileFormat::Latex);
    assert!(out.contains("\\documentclass"), "no preamble: {out}");
    assert!(out.contains("\\section"), "no \\section: {out}");
    assert!(out.contains("\\textbf{bold}"), "no \\textbf: {out}");
    assert!(out.contains("\\begin{itemize}"), "no itemize: {out}");
    assert!(out.contains("\\end{document}"), "no document end: {out}");
}

#[test]
fn rtf_target_is_well_formed_and_bold() {
    let out = convert(FileFormat::Rtf);
    assert!(out.starts_with("{\\rtf1"), "no rtf header: {out}");
    assert!(out.ends_with('}'), "rtf not closed: {out}");
    assert!(out.contains("\\b "), "no bold control word: {out}");
    assert!(out.contains("Title"), "heading text lost: {out}");
}

#[test]
fn org_target_has_star_heading_and_bold() {
    let out = convert(FileFormat::Org);
    assert!(out.contains("* Title"), "no org heading: {out}");
    assert!(out.contains("*bold*"), "no org bold: {out}");
    assert!(out.contains("- one"), "no org list item: {out}");
}

#[test]
fn rst_target_has_underlined_heading_and_bold() {
    let out = convert(FileFormat::Rst);
    // The RST heading underlines the title with '=' repeated at least its length.
    assert!(out.contains("Title\n===="), "no rst heading underline: {out}");
    assert!(out.contains("**bold**"), "no rst bold: {out}");
    assert!(out.contains("- one"), "no rst list item: {out}");
}

#[test]
fn adoc_target_has_equals_heading_and_bold() {
    let out = convert(FileFormat::AsciiDoc);
    // Markdown H1 maps to AsciiDoc level-2 ("== ").
    assert!(out.contains("== Title"), "no adoc heading: {out}");
    assert!(out.contains("*bold*"), "no adoc bold: {out}");
    assert!(out.contains("* one"), "no adoc list item: {out}");
}

#[test]
fn ipynb_target_is_valid_json_with_a_markdown_cell() {
    let out = convert(FileFormat::Ipynb);
    let v: serde_json::Value = serde_json::from_str(&out).expect("ipynb is valid JSON");
    assert_eq!(v["nbformat"], 4, "not nbformat 4: {out}");
    let cells = v["cells"].as_array().expect("cells array");
    assert!(
        cells.iter().any(|c| c["cell_type"] == "markdown"),
        "no markdown cell: {out}"
    );
    assert!(out.contains("Title"), "heading text lost: {out}");
}

#[test]
fn typst_target_has_equals_heading_and_bold() {
    let out = convert(FileFormat::Typst);
    assert!(out.contains("#set page"), "no typst preamble: {out}");
    assert!(out.contains("= Title"), "no typst heading: {out}");
    assert!(out.contains("*bold*"), "no typst bold: {out}");
}

// ── Declared-lossy math: carried as LaTeX source, never dropped ──────────────

#[test]
fn tex_target_keeps_display_math_as_latex_equation() {
    let md = "Before.\n\n$$E = mc^2$$\n\nAfter.\n";
    let out = String::from_utf8(
        convert_file(md.as_bytes(), FileFormat::Markdown, FileFormat::Latex).unwrap(),
    )
    .unwrap();
    assert!(out.contains("\\begin{equation}"), "no equation env: {out}");
    assert!(out.contains("E = mc^2"), "latex source lost: {out}");
}

#[test]
fn plaintext_target_strips_math_delimiters_keeps_source() {
    let md = "$$E = mc^2$$\n";
    let out = String::from_utf8(
        convert_file(md.as_bytes(), FileFormat::Markdown, FileFormat::PlainText).unwrap(),
    )
    .unwrap();
    assert!(out.contains("E = mc^2"), "math source lost: {out}");
    assert!(!out.contains("$$"), "delimiters not stripped: {out}");
}

// ── Refusals, by name (invariant 2) ──────────────────────────────────────────

#[test]
fn unsupported_container_target_is_refused_by_name() {
    // DOCX: the copied exporter links the Typst equation-image renderer, excluded
    // in this build. Refuse by name with the exact reason.
    let err = convert_file(SRC.as_bytes(), FileFormat::Markdown, FileFormat::Docx).unwrap_err();
    match &err {
        ConvertError::UnsupportedTarget { target, reason } => {
            assert_eq!(*target, "DOCX");
            assert!(reason.contains("Typst"), "reason omits the blocker: {reason}");
        }
        other => panic!("expected UnsupportedTarget, got {other:?}"),
    }
    assert!(err.to_string().contains("DOCX"));
}

#[test]
fn epub_and_odt_targets_are_refused_by_name() {
    for t in [FileFormat::Epub, FileFormat::Odt] {
        let err = convert_file(SRC.as_bytes(), FileFormat::Markdown, t).unwrap_err();
        assert!(
            matches!(err, ConvertError::UnsupportedTarget { .. }),
            "expected UnsupportedTarget for {t:?}, got {err:?}"
        );
    }
}

#[test]
fn unextractable_source_is_refused_by_name() {
    // A PNG source carries no extractable document text; even with a supported
    // target the conversion refuses, naming the source format (invariant 2).
    let png = b"\x89PNG\r\n\x1a\n";
    let err = convert_file(png, FileFormat::Png, FileFormat::Html).unwrap_err();
    match &err {
        ConvertError::Source(files_err) => {
            assert!(
                files_err.to_string().contains("PNG"),
                "source error does not name PNG: {files_err}"
            );
        }
        other => panic!("expected Source error naming PNG, got {other:?}"),
    }
}

#[test]
fn import_only_format_is_not_a_target() {
    // MediaWiki is import-only in the reused engine: no exporter to copy.
    let err = convert_file(SRC.as_bytes(), FileFormat::Markdown, FileFormat::Wiki).unwrap_err();
    assert!(matches!(err, ConvertError::UnsupportedTarget { .. }));
}

// ── PDF: a browser-backed target (Phase D1), never launched from a test ───────

#[test]
fn pdf_target_availability_is_a_callable_probe() {
    // Detection only: reports whether a PDF-capable browser (Chrome/Edge) exists.
    // It must return without launching anything, whatever the host answer is.
    let _available: bool = stegano_files::pdf_target_available();
}

#[test]
fn converting_an_image_source_to_pdf_is_refused_by_name() {
    // The PDF branch still extracts to the Markdown waypoint first: an image source
    // carries no document text, so the conversion refuses by name BEFORE any browser
    // is involved (invariant 2). This never launches a browser.
    let png = b"\x89PNG\r\n\x1a\n";
    let err = convert_file(png, FileFormat::Png, FileFormat::Pdf).unwrap_err();
    match &err {
        ConvertError::Source(files_err) => {
            assert!(
                files_err.to_string().contains("PNG"),
                "source error does not name PNG: {files_err}"
            );
        }
        other => panic!("expected Source error naming PNG, got {other:?}"),
    }
}

#[test]
fn converting_a_pdf_source_is_refused_by_name() {
    // PDF is output-only: a PDF SOURCE is refused by name regardless of target, so
    // it can never become a mark carrier or a conversion source. No browser here.
    let err = convert_file(b"%PDF-1.7\n", FileFormat::Pdf, FileFormat::Pdf).unwrap_err();
    match &err {
        ConvertError::Source(files_err) => {
            assert!(
                files_err.to_string().contains("PDF"),
                "source error does not name PDF: {files_err}"
            );
        }
        other => panic!("expected Source error naming PDF, got {other:?}"),
    }
}

#[test]
fn markdown_to_pdf_on_a_browserless_host_is_refused_by_name() {
    // On a host with NO PDF-capable browser, converting to PDF must be refused by
    // name (invariant 2), never handed an empty file. On a host that HAS a browser,
    // actually converting would launch it (forbidden in a unit test: flaky, can hang
    // or pop a window), so we assert only that detection reports availability and
    // stop short of the launch. The browserless refusal path and the detection logic
    // are covered deterministically by the `pdf` module's injected-detection unit
    // tests; the real-browser end-to-end is an `#[ignore]`d test there.
    if stegano_files::pdf_target_available() {
        return;
    }
    let err = convert_file(SRC.as_bytes(), FileFormat::Markdown, FileFormat::Pdf).unwrap_err();
    match &err {
        ConvertError::NoPdfEngine { detail } => {
            assert!(
                detail.contains("browser") || detail.contains("Firefox"),
                "NoPdfEngine detail is not descriptive: {detail}"
            );
        }
        other => panic!("expected NoPdfEngine, got {other:?}"),
    }
}

// ── source == target is a defined, valid pass ────────────────────────────────

#[test]
fn source_equals_target_html_normalises_through_markdown() {
    // HTML -> HTML still routes through the Markdown waypoint, so it normalises
    // rather than reproducing the input byte-for-byte. It must still be valid HTML.
    let html = "<h1>Heading</h1><p>Body <b>x</b></p>";
    let out = String::from_utf8(
        convert_file(html.as_bytes(), FileFormat::Html, FileFormat::Html).unwrap(),
    )
    .unwrap();
    assert!(out.contains("<h1>Heading</h1>"), "heading lost on normalise: {out}");
}
