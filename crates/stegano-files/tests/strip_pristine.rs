//! File-level SEC-STRIP and SEC-PRISTINE surfacing.
//!
//! `strip_file` removes a document's metadata surfaces with the readable content
//! byte-identical, and a format with no strippable metadata container is refused
//! by name. `pristine_file` (text-native) removes every mark class AND every
//! remaining invisible so the text re-analyses fully clean, and names the
//! meaning-bearing trade-off; a container is refused by name.

use std::io::{Cursor, Write};

use stegano_files::{pristine_file, strip_file, FileFormat, TransformError, DOCX_METADATA_ENTRY};

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, content) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(content).unwrap();
        }
        w.finish().unwrap();
    }
    buf
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
    let idat_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&png_chunk(b"tEXt", b"steganohero\0payload"));
    png.extend_from_slice(&png_chunk(b"IDAT", &idat_data));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));
    (png, png_chunk(b"IDAT", &idat_data))
}

#[test]
fn strip_file_removes_metadata_and_reports_content_identical() {
    let (png, idat_chunk) = png_with_metadata();

    let out = strip_file(&png, FileFormat::Png).expect("a valid PNG strips");

    assert!(out.altered, "metadata was present, so the strip changes the bytes");
    assert!(out.content_identical, "a strip never touches the readable content");
    // The metadata text chunk is gone.
    assert!(
        !out.bytes.windows(4).any(|w| w == b"tEXt"),
        "the tEXt metadata chunk is removed"
    );
    // The pixel data survives byte-identical.
    assert!(
        out.bytes.windows(idat_chunk.len()).any(|w| w == idat_chunk.as_slice()),
        "the IDAT (pixel) chunk is preserved verbatim"
    );
}

#[test]
fn strip_file_on_a_format_without_a_metadata_container_is_refused_by_name() {
    let md = b"# Title\n\nBody text, no metadata container.\n";
    let err = strip_file(md, FileFormat::Markdown).expect_err("markdown has no metadata surface");
    // Named refusal, not a silent no-op returning the input unchanged (invariant 2).
    assert!(
        matches!(err, TransformError::Strip(_)),
        "the refusal names the strip layer, got: {err}"
    );
}

#[test]
fn pristine_file_text_native_removes_marks_and_invisibles_and_names_the_tradeoff() {
    // A zero-width mark, an orphan invisible separator (U+2063) and a soft hyphen
    // (U+00AD): none may survive a pristine clean.
    let dirty = "# Note\n\nHello\u{200B}world\u{2063} and\u{00AD} more.\n";

    let out = pristine_file(dirty.as_bytes(), FileFormat::Markdown).expect("markdown pristine");

    assert!(out.altered, "the dirty text changed");
    assert!(
        !out.cleaned_text.chars().any(is_invisible_like),
        "no invisible or format-control character remains: {:?}",
        out.cleaned_text
    );
    assert!(
        out.invisibles_removed >= 1,
        "the orphan invisibles were counted, got {}",
        out.invisibles_removed
    );
    assert!(
        !out.notes.is_empty(),
        "the meaning-bearing trade-off is named, never silent"
    );
    // The visible words survive.
    assert!(out.cleaned_text.contains("Hello"));
    assert!(out.cleaned_text.contains("world"));
    assert!(out.cleaned_text.contains("more"));
}

#[test]
fn pristine_file_on_a_container_is_refused_by_name() {
    // A well-formed DOCX whose body extracts to text, so pristine reaches the
    // container arm (not an extraction error) and refuses the combination by name.
    let doc_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n\
  <w:body><w:p><w:r><w:t xml:space=\"preserve\">Hello provenance world</w:t></w:r></w:p></w:body>\n\
</w:document>";
    let docx = build_zip(&[
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>"),
        ("_rels/.rels", b"<?xml version=\"1.0\"?><Relationships/>"),
        ("word/document.xml", doc_xml.as_bytes()),
        (DOCX_METADATA_ENTRY, b"c3RlZ2Fubw=="),
    ]);

    let err = pristine_file(&docx, FileFormat::Docx).expect_err("container pristine is refused");
    assert!(
        matches!(err, TransformError::UnsupportedCombination { .. }),
        "the refusal names the unsupported combination, got: {err}"
    );
}

/// Invisible or format-control characters that a pristine clean must remove.
fn is_invisible_like(c: char) -> bool {
    matches!(c as u32,
        0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069
        | 0xFEFF | 0x00AD | 0x034F | 0x061C | 0x180E)
}
