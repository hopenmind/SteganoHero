//! Text extraction over the wider format set added in the file-intake widening
//! (Phase A): EPUB, PPTX, RTF, LaTeX, Org, reStructuredText, MediaWiki, AsciiDoc,
//! Typst, Jupyter, BibTeX, FictionBook, email, CSV/TSV, and source code.
//!
//! Every fixture is built in-memory (a ZIP for the container formats, a string
//! for the rest), so the suite needs no on-disk corpus. Each format has an
//! extraction test that asserts the expected readable text comes out, plus the
//! raise-by-name refusals: malformed containers, a container missing its content,
//! and the honest "nothing readable" refusals for the text formats.

use std::io::{Cursor, Write};

use stegano_files::{
    clean_file, extract_text, inspect_file, Container, FileFormat, FilesError, TransformError,
};

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

fn extract(bytes: &[u8], format: FileFormat) -> String {
    let out = extract_text(bytes, format).unwrap();
    assert_eq!(out.format, format);
    // Every widened format lowers its source to Markdown: it must NOT claim to be
    // a text-native or Office-container document (that would mislead write-back).
    assert!(
        matches!(out.container, Container::Lowered),
        "expected Container::Lowered for {format:?}, got {:?}",
        out.container
    );
    out.text
}

// ── EPUB ──────────────────────────────────────────────────────────────────────

fn epub_fixture() -> Vec<u8> {
    build_zip(&[
        ("mimetype", "application/epub+zip"),
        (
            "META-INF/container.xml",
            r#"<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>"#,
        ),
        (
            "OEBPS/content.opf",
            r#"<?xml version="1.0"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <manifest>
    <item id="ch1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine>
    <itemref idref="ch1"/>
  </spine>
</package>"#,
        ),
        (
            "OEBPS/chapter1.xhtml",
            r#"<html><body><h1>Chapter One</h1><p>The wolf howled at dusk.</p></body></html>"#,
        ),
    ])
}

#[test]
fn epub_extracts_chapter_text() {
    let text = extract(&epub_fixture(), FileFormat::Epub);
    assert!(text.contains("Chapter One"), "heading missing: {text:?}");
    assert!(text.contains("The wolf howled at dusk."), "body missing: {text:?}");
}

#[test]
fn corrupt_epub_raises_by_name() {
    let err = extract_text(b"this is not a zip", FileFormat::Epub).unwrap_err();
    assert!(matches!(err, FilesError::Extraction { format: "EPUB", .. }));
    assert!(err.to_string().contains("EPUB"));
}

#[test]
fn epub_without_container_descriptor_raises_by_name() {
    let not_an_epub = build_zip(&[("some/other.xml", "<root/>")]);
    let err = extract_text(&not_an_epub, FileFormat::Epub).unwrap_err();
    match &err {
        FilesError::Extraction { format, detail } => {
            assert_eq!(*format, "EPUB");
            assert!(detail.contains("container.xml"), "detail names the missing part: {detail}");
        }
        other => panic!("expected Extraction, got {other:?}"),
    }
}

// ── PPTX ──────────────────────────────────────────────────────────────────────

fn pptx_fixture() -> Vec<u8> {
    build_zip(&[(
        "ppt/slides/slide1.xml",
        r#"<p:sld xmlns:p="p" xmlns:a="a"><p:cSld><p:spTree>
  <p:sp><p:nvSpPr><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr>
    <p:txBody><a:p><a:r><a:t>Quarterly Review</a:t></a:r></a:p></p:txBody></p:sp>
  <p:sp><p:nvSpPr><p:nvPr><p:ph type="body"/></p:nvPr></p:nvSpPr>
    <p:txBody><a:p><a:r><a:t>Revenue up sharply</a:t></a:r></a:p></p:txBody></p:sp>
</p:spTree></p:cSld></p:sld>"#,
    )])
}

#[test]
fn pptx_extracts_slide_title_and_body() {
    let text = extract(&pptx_fixture(), FileFormat::Pptx);
    assert!(text.contains("Quarterly Review"), "slide title missing: {text:?}");
    assert!(text.contains("Revenue up sharply"), "slide body missing: {text:?}");
}

#[test]
fn corrupt_pptx_raises_by_name() {
    let err = extract_text(b"\x00\x01 not a zip", FileFormat::Pptx).unwrap_err();
    assert!(matches!(err, FilesError::Extraction { format: "PPTX", .. }));
    assert!(err.to_string().contains("PPTX"));
}

#[test]
fn pptx_without_slides_raises_by_name() {
    let no_slides = build_zip(&[("ppt/presentation.xml", "<p:presentation/>")]);
    let err = extract_text(&no_slides, FileFormat::Pptx).unwrap_err();
    match &err {
        FilesError::Extraction { format, detail } => {
            assert_eq!(*format, "PPTX");
            assert!(detail.contains("no slides"), "detail names the reason: {detail}");
        }
        other => panic!("expected Extraction, got {other:?}"),
    }
}

// ── RTF ───────────────────────────────────────────────────────────────────────

#[test]
fn rtf_extracts_text_and_bold() {
    let rtf = r"{\rtf1\ansi Hello \b bold\b0  world\par}";
    let text = extract(rtf.as_bytes(), FileFormat::Rtf);
    assert!(text.contains("Hello"), "plain text missing: {text:?}");
    assert!(text.contains("**bold**"), "bold run missing: {text:?}");
    assert!(text.contains("world"), "trailing text missing: {text:?}");
}

// ── LaTeX ─────────────────────────────────────────────────────────────────────

#[test]
fn latex_extracts_section_and_bold() {
    let tex = r"\documentclass{article}
\begin{document}
\section{Results}
We found \textbf{strong} evidence.
\end{document}";
    let text = extract(tex.as_bytes(), FileFormat::Latex);
    assert!(text.contains("## Results"), "section heading missing: {text:?}");
    assert!(text.contains("**strong**"), "bold run missing: {text:?}");
    assert!(text.contains("evidence."), "body missing: {text:?}");
}

// ── Org ───────────────────────────────────────────────────────────────────────

#[test]
fn org_extracts_title_heading_and_emphasis() {
    let org = "#+TITLE: My Notes\n\n* Section One\nSome *bold* text.\n";
    let text = extract(org.as_bytes(), FileFormat::Org);
    assert!(text.contains("My Notes"), "title missing: {text:?}");
    assert!(text.contains("Section One"), "heading missing: {text:?}");
    assert!(text.contains("**bold**"), "emphasis missing: {text:?}");
}

// ── reStructuredText ───────────────────────────────────────────────────────────

#[test]
fn rst_extracts_heading_and_code_span() {
    let rst = "Title Here\n==========\n\nSome text with ``code`` inline.\n";
    let text = extract(rst.as_bytes(), FileFormat::Rst);
    assert!(text.contains("# Title Here"), "underlined heading missing: {text:?}");
    assert!(text.contains("`code`"), "code span missing: {text:?}");
}

// ── MediaWiki ──────────────────────────────────────────────────────────────────

#[test]
fn wiki_extracts_heading_and_emphasis() {
    let wiki = "== Heading ==\n\n'''bold''' and ''italic''\n";
    let text = extract(wiki.as_bytes(), FileFormat::Wiki);
    assert!(text.contains("## Heading"), "heading missing: {text:?}");
    assert!(text.contains("**bold**"), "bold missing: {text:?}");
    assert!(text.contains("*italic*"), "italic missing: {text:?}");
}

// ── AsciiDoc ───────────────────────────────────────────────────────────────────

#[test]
fn asciidoc_extracts_title_and_emphasis() {
    let adoc = "= Document Title\n\nSome *bold* and _italic_ words.\n";
    let text = extract(adoc.as_bytes(), FileFormat::AsciiDoc);
    assert!(text.contains("# Document Title"), "title missing: {text:?}");
    assert!(text.contains("**bold**"), "bold missing: {text:?}");
    assert!(text.contains("*italic*"), "italic missing: {text:?}");
}

// ── Typst ──────────────────────────────────────────────────────────────────────

#[test]
fn typst_extracts_heading_and_emphasis() {
    let typ = "= Title\n\nSome *bold* text with _italic_.\n";
    let text = extract(typ.as_bytes(), FileFormat::Typst);
    assert!(text.contains("# Title"), "heading missing: {text:?}");
    assert!(text.contains("**bold**"), "bold missing: {text:?}");
    assert!(text.contains("*italic*"), "italic missing: {text:?}");
}

// ── Jupyter ────────────────────────────────────────────────────────────────────

#[test]
fn ipynb_extracts_markdown_and_code_cells() {
    let ipynb = r##"{
      "cells": [
        {"cell_type": "markdown", "source": ["# Notebook\n", "\n", "Intro text."]},
        {"cell_type": "code", "source": "print('hi')", "outputs": []}
      ],
      "metadata": {"kernelspec": {"language": "python"}}
    }"##;
    let text = extract(ipynb.as_bytes(), FileFormat::Ipynb);
    assert!(text.contains("# Notebook"), "markdown cell missing: {text:?}");
    assert!(text.contains("Intro text."), "markdown body missing: {text:?}");
    assert!(text.contains("```python"), "code fence language missing: {text:?}");
    assert!(text.contains("print('hi')"), "code cell missing: {text:?}");
}

#[test]
fn malformed_ipynb_raises_by_name() {
    let err = extract_text(b"{ not valid json", FileFormat::Ipynb).unwrap_err();
    match &err {
        FilesError::Extraction { format, detail } => {
            assert_eq!(*format, "Jupyter");
            assert!(detail.to_lowercase().contains("json"), "detail names JSON: {detail}");
        }
        other => panic!("expected Extraction, got {other:?}"),
    }
}

// ── BibTeX ─────────────────────────────────────────────────────────────────────

#[test]
fn bibtex_extracts_reference_entry() {
    let bib = "@article{key1,\n  title = {A Great Paper},\n  author = {Doe, Jane},\n  year = {2020},\n  journal = {Nature}\n}\n";
    let text = extract(bib.as_bytes(), FileFormat::Bibtex);
    assert!(text.contains("# References"), "header missing: {text:?}");
    assert!(text.contains("**A Great Paper**"), "title missing: {text:?}");
    assert!(text.contains("Doe J."), "author missing: {text:?}");
    assert!(text.contains("2020"), "year missing: {text:?}");
    assert!(text.contains("Nature"), "venue missing: {text:?}");
}

#[test]
fn bibtex_without_entries_raises_by_name() {
    // A .bib file that carries no @entry is not a usable bibliography: refuse by
    // name rather than hand back a lone "# References" header (invariant 2).
    let err = extract_text(b"this file has no entries at all\n", FileFormat::Bibtex).unwrap_err();
    assert!(matches!(err, FilesError::Extraction { format: "BibTeX", .. }));
}

// ── FictionBook ────────────────────────────────────────────────────────────────

#[test]
fn fb2_extracts_title_and_emphasis() {
    let fb2 = r#"<?xml version="1.0"?>
<FictionBook><body><section>
  <title><p>Chapter</p></title>
  <p>The story <emphasis>begins</emphasis> here.</p>
</section></body></FictionBook>"#;
    let text = extract(fb2.as_bytes(), FileFormat::Fb2);
    assert!(text.contains("Chapter"), "title missing: {text:?}");
    assert!(text.contains("The story"), "body missing: {text:?}");
    assert!(text.contains("*begins*"), "emphasis missing: {text:?}");
}

#[test]
fn fb2_without_body_raises_by_name() {
    let fb2 = r#"<?xml version="1.0"?><FictionBook><description>only metadata</description></FictionBook>"#;
    let err = extract_text(fb2.as_bytes(), FileFormat::Fb2).unwrap_err();
    assert!(matches!(err, FilesError::Extraction { format: "FictionBook", .. }));
}

// ── Email ──────────────────────────────────────────────────────────────────────

#[test]
fn eml_extracts_subject_headers_and_body() {
    let eml = "From: alice@example.com\nTo: bob@example.com\nSubject: Meeting\n\nLet's meet at noon.\n";
    let text = extract(eml.as_bytes(), FileFormat::Eml);
    assert!(text.contains("# Meeting"), "subject heading missing: {text:?}");
    assert!(text.contains("alice@example.com"), "from header missing: {text:?}");
    assert!(text.contains("Let's meet at noon."), "body missing: {text:?}");
}

// ── CSV / TSV ──────────────────────────────────────────────────────────────────

#[test]
fn csv_extracts_pipe_table() {
    let csv = "name,role\nAlice,Engineer\nBob,Designer\n";
    let text = extract(csv.as_bytes(), FileFormat::Csv);
    assert!(text.contains("| name | role |"), "header row missing: {text:?}");
    assert!(text.contains("| --- | --- |"), "delimiter row missing: {text:?}");
    assert!(text.contains("| Alice | Engineer |"), "data row missing: {text:?}");
}

#[test]
fn tsv_extension_maps_to_csv_and_extracts() {
    assert_eq!(FileFormat::from_extension("tsv").unwrap(), FileFormat::Csv);
    let tsv = "name\trole\nAlice\tEngineer\n";
    let text = extract(tsv.as_bytes(), FileFormat::Csv);
    assert!(text.contains("| name | role |"), "tab-delimited header missing: {text:?}");
    assert!(text.contains("| Alice | Engineer |"), "tab-delimited row missing: {text:?}");
}

#[test]
fn empty_csv_raises_by_name() {
    let err = extract_text(b"   \n  \n", FileFormat::Csv).unwrap_err();
    assert!(matches!(err, FilesError::Extraction { format: "CSV", .. }));
}

// ── Source code ────────────────────────────────────────────────────────────────

#[test]
fn source_code_extension_carries_language() {
    assert_eq!(FileFormat::from_extension("rs").unwrap(), FileFormat::Code("rust"));
    assert_eq!(FileFormat::from_extension("py").unwrap(), FileFormat::Code("python"));
    assert_eq!(FileFormat::from_extension("cpp").unwrap(), FileFormat::Code("cpp"));
}

#[test]
fn source_code_extracts_fenced_block() {
    let code = "fn main() {\n    println!(\"hi\");\n}\n";
    let text = extract(code.as_bytes(), FileFormat::Code("rust"));
    assert!(text.contains("```rust"), "fence language missing: {text:?}");
    assert!(text.contains("fn main()"), "code body missing: {text:?}");
}

// ── Unsupported extension still refuses ─────────────────────────────────────────

#[test]
fn unknown_extension_raises_by_name() {
    let err = FileFormat::from_extension("xyz").unwrap_err();
    match &err {
        FilesError::Unsupported(ext) => assert_eq!(ext, "xyz"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// ── Transform behaviour over a lowered format ──────────────────────────────────

#[test]
fn inspect_works_on_a_lowered_format() {
    // Inspect is read-only and must work on every readable format, lowered ones
    // included: it just reads the extracted text.
    let rtf = r"{\rtf1\ansi A plain sentence.\par}";
    let report = inspect_file(rtf.as_bytes(), FileFormat::Rtf).unwrap();
    // A clean cover carries no marks; the report is produced without error.
    let _ = report;
}

#[test]
fn clean_is_refused_by_name_on_a_lowered_format() {
    // A lowered format has no proven lossless write-back this build, so clean is
    // refused BY NAME rather than approximated (invariant 2).
    let rtf = r"{\rtf1\ansi A plain sentence.\par}";
    let err = clean_file(rtf.as_bytes(), FileFormat::Rtf, &[]).unwrap_err();
    match &err {
        TransformError::UnsupportedCombination { operation, format, .. } => {
            assert_eq!(*operation, "clean");
            assert_eq!(*format, "RTF");
        }
        other => panic!("expected UnsupportedCombination, got {other:?}"),
    }
}
