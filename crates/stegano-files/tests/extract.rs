//! Text extraction over minimal real fixtures: a DOCX and an ODT built
//! in-memory as ZIP archives, an HTML string, and a plain-text path round-trip.
//! Plus the raise-by-name cases: a corrupt container, a missing content part,
//! and an unsupported format.

use std::io::{Cursor, Write};

use stegano_files::{extract_text, extract_text_from_path, Container, FileFormat, FilesError};

/// Build a ZIP archive in memory from (entry-name, content) pairs, using stored
/// (uncompressed) entries so the fixture needs no compression codec.
fn build_zip(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, content) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(content.as_bytes()).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

const DOCX_DOCUMENT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Provenance Report</w:t></w:r></w:p>
    <w:p><w:r><w:t xml:space="preserve">The quick brown </w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>fox</w:t></w:r><w:r><w:t> jumps.</w:t></w:r></w:p>
  </w:body>
</w:document>"#;

fn docx_fixture() -> Vec<u8> {
    build_zip(&[("word/document.xml", DOCX_DOCUMENT_XML)])
}

const ODT_CONTENT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
  <office:body><office:text>
    <text:h text:outline-level="1">Sovereignty Notes</text:h>
    <text:p>A plain paragraph of body text.</text:p>
  </office:text></office:body>
</office:document-content>"#;

fn odt_fixture() -> Vec<u8> {
    build_zip(&[("content.xml", ODT_CONTENT_XML)])
}

const HTML_FIXTURE: &str = r#"<html>
<head><title>ignored</title><style>.a{color:red}</style></head>
<body>
<h1>Marked Document</h1>
<p>Body with <strong>emphasis</strong> here.</p>
<script>var secret = 1;</script>
</body></html>"#;

#[test]
fn docx_extracts_visible_text() {
    let out = extract_text(&docx_fixture(), FileFormat::Docx).unwrap();
    assert_eq!(out.format, FileFormat::Docx);
    assert!(out.text.contains("Provenance Report"), "heading missing: {:?}", out.text);
    assert!(out.text.contains("The quick brown"), "body missing: {:?}", out.text);
    assert!(out.text.contains("**fox**"), "bold run missing: {:?}", out.text);
    assert!(out.text.contains("jumps."), "tail run missing: {:?}", out.text);
}

#[test]
fn docx_retains_original_container_for_write_back() {
    let bytes = docx_fixture();
    let out = extract_text(&bytes, FileFormat::Docx).unwrap();
    match out.container {
        Container::OfficeZip { archive, entry, xml } => {
            assert_eq!(entry, "word/document.xml");
            assert_eq!(archive, bytes, "the original archive is retained untouched");
            assert!(xml.contains("<w:t>"), "the primary part XML is retained");
        }
        other => panic!("expected OfficeZip container, got {other:?}"),
    }
}

#[test]
fn odt_extracts_visible_text() {
    let out = extract_text(&odt_fixture(), FileFormat::Odt).unwrap();
    assert_eq!(out.format, FileFormat::Odt);
    assert!(out.text.contains("Sovereignty Notes"), "heading missing: {:?}", out.text);
    assert!(out.text.contains("A plain paragraph of body text."), "body missing: {:?}", out.text);
}

#[test]
fn html_extracts_visible_text_and_drops_scripts_and_styles() {
    let out = extract_text(HTML_FIXTURE.as_bytes(), FileFormat::Html).unwrap();
    assert_eq!(out.format, FileFormat::Html);
    assert!(out.text.contains("Marked Document"), "heading missing: {:?}", out.text);
    assert!(out.text.contains("**emphasis**"), "bold run missing: {:?}", out.text);
    assert!(!out.text.contains("var secret"), "script body leaked: {:?}", out.text);
    assert!(!out.text.contains("color:red"), "style body leaked: {:?}", out.text);
    // HTML retains its original markup for a faithful later write-back.
    assert!(matches!(out.container, Container::Markup { .. }));
}

#[test]
fn corrupt_docx_raises_by_name() {
    let err = extract_text(b"this is not a zip archive", FileFormat::Docx).unwrap_err();
    match &err {
        FilesError::Extraction { format, .. } => assert_eq!(*format, "DOCX"),
        other => panic!("expected Extraction, got {other:?}"),
    }
    assert!(err.to_string().contains("DOCX"), "error must name the format: {err}");
}

#[test]
fn corrupt_odt_raises_by_name() {
    let err = extract_text(b"\x00\x01 not a zip", FileFormat::Odt).unwrap_err();
    assert!(matches!(err, FilesError::Extraction { format: "ODT", .. }));
    assert!(err.to_string().contains("ODT"));
}

#[test]
fn docx_without_document_part_raises_by_name() {
    // A valid ZIP that is not a DOCX (no word/document.xml) must refuse, not blank.
    let not_a_docx = build_zip(&[("some/other.xml", "<root/>")]);
    let err = extract_text(&not_a_docx, FileFormat::Docx).unwrap_err();
    match &err {
        FilesError::Extraction { format, detail } => {
            assert_eq!(*format, "DOCX");
            assert!(detail.contains("document.xml"), "detail names the missing part: {detail}");
        }
        other => panic!("expected Extraction, got {other:?}"),
    }
}

#[test]
fn unsupported_format_by_path_raises_by_name() {
    // PDF import is the named gap in this build: path inference refuses `.pdf` by
    // name. (PDF is a convert TARGET only; it is never inferred as a source.)
    let err = extract_text_from_path(std::path::Path::new("report.pdf")).unwrap_err();
    match &err {
        FilesError::Unsupported(ext) => assert_eq!(ext, "pdf"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn pdf_source_is_refused_by_name() {
    // Even when the PDF variant is constructed directly (only ever as a target),
    // extracting text from it must refuse by name rather than return empty or a
    // partial parse (invariant 2).
    let err = extract_text(b"%PDF-1.7\n", FileFormat::Pdf).unwrap_err();
    match &err {
        FilesError::Extraction { format, .. } => assert_eq!(*format, "PDF"),
        other => panic!("expected Extraction naming PDF, got {other:?}"),
    }
    assert!(err.to_string().contains("PDF"));
}

#[test]
fn extract_from_path_reads_and_infers_format() {
    let mut path = std::env::temp_dir();
    path.push(format!("stegano_files_test_{}.md", std::process::id()));
    std::fs::write(&path, "# Title\n\nA marked paragraph.\n").unwrap();

    let out = extract_text_from_path(&path).unwrap();
    assert_eq!(out.format, FileFormat::Markdown);
    assert!(out.text.contains("# Title"));
    assert!(out.text.contains("A marked paragraph."));

    let _ = std::fs::remove_file(&path);
}
