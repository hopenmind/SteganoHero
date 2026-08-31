//! Native metadata READ (the analyse side of the metadata pillar): read the
//! standard metadata a document format exposes itself. These tests build minimal
//! DOCX and ODT archives in memory (a `docProps/core.xml` + `app.xml` +
//! `custom.xml` for DOCX, a `meta.xml` for ODT), prove the standard fields and a
//! custom property are read, prove an absent part is an empty-but-explicit result
//! (not an error), prove a format with no native reader is refused BY NAME, and
//! prove malformed docProps raises BY NAME (invariant 2).

use std::io::{Cursor, Write};

use stegano_files::{read_native_metadata, FileFormat, MetadataError};

/// Build a Stored (uncompressed) ZIP from name/content pairs.
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

const CORE_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<cp:coreProperties \
xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" \
xmlns:dc=\"http://purl.org/dc/elements/1.1/\" \
xmlns:dcterms=\"http://purl.org/dc/terms/\" \
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\
<dc:title>Quarterly Report</dc:title>\
<dc:subject>Finance</dc:subject>\
<dc:creator>Ada Lovelace</dc:creator>\
<cp:keywords>finance, q3, internal</cp:keywords>\
<dc:description>Internal draft</dc:description>\
<cp:lastModifiedBy>Grace Hopper</cp:lastModifiedBy>\
<cp:category>Reports</cp:category>\
<dcterms:created xsi:type=\"dcterms:W3CDTF\">2026-01-02T09:00:00Z</dcterms:created>\
<dcterms:modified xsi:type=\"dcterms:W3CDTF\">2026-02-03T10:30:00Z</dcterms:modified>\
</cp:coreProperties>";

const APP_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Properties \
xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" \
xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">\
<Application>Microsoft Office Word</Application>\
<Company>Hope 'n Mind</Company>\
<Words>1234</Words>\
<Pages>7</Pages>\
<Characters>6789</Characters>\
</Properties>";

const CUSTOM_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Properties \
xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties\" \
xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">\
<property fmtid=\"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}\" pid=\"2\" name=\"Classification\">\
<vt:lpwstr>Confidential</vt:lpwstr></property>\
</Properties>";

const ODT_META_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<office:document-meta \
xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
xmlns:meta=\"urn:oasis:names:tc:opendocument:xmlns:meta:1.0\" \
xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
<office:meta>\
<dc:title>Manifesto</dc:title>\
<dc:subject>Ideas</dc:subject>\
<dc:description>An outline</dc:description>\
<meta:initial-creator>Alan Turing</meta:initial-creator>\
<dc:creator>Katherine Johnson</dc:creator>\
<meta:creation-date>2025-05-05T05:05:05</meta:creation-date>\
<dc:date>2025-06-06T06:06:06</dc:date>\
<meta:keyword>research</meta:keyword>\
<meta:keyword>draft</meta:keyword>\
<meta:user-defined meta:name=\"Project\">SteganoHero</meta:user-defined>\
</office:meta>\
</office:document-meta>";

#[test]
fn docx_native_reads_core_app_and_custom() {
    let docx = build_zip(&[
        ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
        ("word/document.xml", "<w:document/>"),
        ("docProps/core.xml", CORE_XML),
        ("docProps/app.xml", APP_XML),
        ("docProps/custom.xml", CUSTOM_XML),
    ]);

    let m = read_native_metadata(&docx, FileFormat::Docx).unwrap();

    assert_eq!(m.format, "docx");
    // Core properties.
    assert_eq!(m.title.as_deref(), Some("Quarterly Report"));
    assert_eq!(m.subject.as_deref(), Some("Finance"));
    assert_eq!(m.creator.as_deref(), Some("Ada Lovelace"));
    assert_eq!(m.keywords.as_deref(), Some("finance, q3, internal"));
    assert_eq!(m.description.as_deref(), Some("Internal draft"));
    assert_eq!(m.last_modified_by.as_deref(), Some("Grace Hopper"));
    assert_eq!(m.category.as_deref(), Some("Reports"));
    assert_eq!(m.created.as_deref(), Some("2026-01-02T09:00:00Z"));
    assert_eq!(m.modified.as_deref(), Some("2026-02-03T10:30:00Z"));
    // Extended (app) properties.
    assert_eq!(m.application.as_deref(), Some("Microsoft Office Word"));
    assert_eq!(m.company.as_deref(), Some("Hope 'n Mind"));
    assert_eq!(m.word_count.as_deref(), Some("1234"));
    assert_eq!(m.page_count.as_deref(), Some("7"));
    assert_eq!(m.character_count.as_deref(), Some("6789"));
    // Custom property.
    assert_eq!(m.custom.len(), 1);
    assert_eq!(m.custom[0].name, "Classification");
    assert_eq!(m.custom[0].value, "Confidential");
}

#[test]
fn odt_native_reads_meta_and_custom() {
    let odt = build_zip(&[
        ("mimetype", "application/vnd.oasis.opendocument.text"),
        ("meta.xml", ODT_META_XML),
    ]);

    let m = read_native_metadata(&odt, FileFormat::Odt).unwrap();

    assert_eq!(m.format, "odt");
    assert_eq!(m.title.as_deref(), Some("Manifesto"));
    assert_eq!(m.subject.as_deref(), Some("Ideas"));
    assert_eq!(m.description.as_deref(), Some("An outline"));
    // dc:creator is the (last) creator; meta:initial-creator is not mapped here.
    assert_eq!(m.creator.as_deref(), Some("Katherine Johnson"));
    assert_eq!(m.created.as_deref(), Some("2025-05-05T05:05:05"));
    assert_eq!(m.modified.as_deref(), Some("2025-06-06T06:06:06"));
    // Two <meta:keyword> values are joined.
    assert_eq!(m.keywords.as_deref(), Some("research, draft"));
    // meta:user-defined custom property.
    assert_eq!(m.custom.len(), 1);
    assert_eq!(m.custom[0].name, "Project");
    assert_eq!(m.custom[0].value, "SteganoHero");
}

#[test]
fn docx_without_docprops_returns_empty_but_explicit_not_an_error() {
    // No docProps parts at all: an absent part is not an error, it is a real
    // "the document declares nothing here" answer.
    let docx = build_zip(&[
        ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
        ("word/document.xml", "<w:document/>"),
    ]);

    let m = read_native_metadata(&docx, FileFormat::Docx).unwrap();
    assert_eq!(m.format, "docx");
    assert_eq!(m, stegano_files::NativeMetadata {
        format: "docx".to_string(),
        ..Default::default()
    });
    assert!(m.title.is_none() && m.creator.is_none() && m.custom.is_empty());
}

#[test]
fn format_without_native_reader_is_refused_by_name() {
    for (format, name) in [
        (FileFormat::PlainText, "text"),
        (FileFormat::Markdown, "markdown"),
        (FileFormat::Html, "html"),
        (FileFormat::Pptx, "pptx"),
        (FileFormat::Epub, "epub"),
        (FileFormat::Png, "png"),
        (FileFormat::Svg, "svg"),
    ] {
        let err = read_native_metadata(b"whatever", format).unwrap_err();
        match &err {
            MetadataError::NoNativeMetadata { format: f } => assert_eq!(*f, name),
            other => panic!("expected NoNativeMetadata for {name}, got {other:?}"),
        }
        assert!(err.to_string().contains(name), "refusal must name {name}: {err}");
    }
}

#[test]
fn malformed_docprops_raises_by_name() {
    // core.xml is present but malformed (mismatched end tag): a present-but-broken
    // part raises by name, it is never half-read or returned empty.
    let docx = build_zip(&[
        ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
        ("word/document.xml", "<w:document/>"),
        (
            "docProps/core.xml",
            "<cp:coreProperties><dc:title>x</dc:mismatch></cp:coreProperties>",
        ),
    ]);

    let err = read_native_metadata(&docx, FileFormat::Docx).unwrap_err();
    match &err {
        MetadataError::NativeUnreadable { format, .. } => assert_eq!(*format, "docx"),
        other => panic!("expected NativeUnreadable naming docx, got {other:?}"),
    }
    assert!(err.to_string().contains("docx"), "must name docx: {err}");
}

#[test]
fn invalid_container_raises_by_name() {
    // Not a ZIP at all: the DOCX native read must refuse by name, not empty.
    let err = read_native_metadata(b"this is not a zip", FileFormat::Docx).unwrap_err();
    match &err {
        MetadataError::NativeUnreadable { format, .. } => assert_eq!(*format, "docx"),
        other => panic!("expected NativeUnreadable naming docx, got {other:?}"),
    }
}
