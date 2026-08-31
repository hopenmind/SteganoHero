//! Transform over real documents: inspect a marked file and see the class,
//! clean a marked Markdown / plain-text / DOCX and prove the write-back is
//! lossless (round-trip through re-extraction, and byte-identity of every
//! untouched archive entry), conceal a secret into a text-native document and
//! prove it round-trips while keeping code and equations byte-identical, and
//! refuse by name the combinations whose write-back this slice cannot prove.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use stegano_core::crypto::ChaCha20;
use stegano_core::stego::ZeroWidth;
use stegano_core::traits::StegoMethod;
use stegano_core::{pipeline, SteganoError};

use stegano_files::{clean_file, conceal_file, inspect_file, FileFormat, MarkClass, TransformError};

// ── Fixture helpers ──────────────────────────────────────────────────────────

/// Build a ZIP archive from (name, content) pairs using stored (uncompressed)
/// entries, so the fixture needs no compression codec.
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

/// Read every entry of a ZIP archive into a name -> decompressed-bytes map, so
/// two archives can be compared entry by entry.
fn read_all_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut map = BTreeMap::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let name = file.name().to_string();
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        map.insert(name, content);
    }
    map
}

/// A cover long enough for the zero-width carrier to place a byte of payload.
const COVER: &str = "The quick brown fox jumps over the lazy dog near the bank";

/// Mark `COVER` with a real zero-width payload, so the fixture provably carries
/// a mark the core's own carrier placed.
fn zero_width_marked() -> String {
    let marked = ZeroWidth::new().encode(COVER, b"x").unwrap();
    assert_ne!(marked, COVER, "the fixture must actually carry a mark");
    marked
}

/// A DOCX document.xml whose body paragraph carries the zero-width mark, split
/// across two runs so the surgical strip is exercised across run boundaries.
fn marked_docx_document_xml(marked: &str) -> String {
    // Split the marked text in half so each half lands in its own <w:t> run.
    let mid = marked.len() / 2;
    // Find a char boundary at or after `mid`.
    let mut split = mid;
    while !marked.is_char_boundary(split) {
        split += 1;
    }
    let (head, tail) = marked.split_at(split);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n\
  <w:body>\n\
    <w:p><w:r><w:t xml:space=\"preserve\">{head}</w:t></w:r><w:r><w:t xml:space=\"preserve\">{tail}</w:t></w:r></w:p>\n\
  </w:body>\n\
</w:document>"
    )
}

/// A minimal multi-entry DOCX carrying the mark, with two sibling entries that
/// must survive a clean byte-for-byte.
fn marked_docx() -> (Vec<u8>, String) {
    let doc_xml = marked_docx_document_xml(&zero_width_marked());
    let content_types = "<?xml version=\"1.0\"?><Types/>";
    let rels = "<?xml version=\"1.0\"?><Relationships/>";
    let bytes = build_zip(&[
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", rels),
        ("word/document.xml", &doc_xml),
    ]);
    (bytes, doc_xml)
}

// ── Inspect ──────────────────────────────────────────────────────────────────

#[test]
fn inspect_a_marked_docx_reports_the_zero_width_class() {
    let (bytes, _) = marked_docx();
    let report = inspect_file(&bytes, FileFormat::Docx).unwrap();

    let zw = report
        .classes
        .iter()
        .find(|c| c.id == "zero_width")
        .expect("zero_width class listed");
    assert!(zw.count > 0, "the marked DOCX must report zero-width marks");
    assert!(report.classes.iter().all(|c| c.cleanable));
}

#[test]
fn inspect_a_plain_document_reports_no_marks() {
    let report = inspect_file(b"# Title\n\nA clean paragraph.\n", FileFormat::Markdown).unwrap();
    assert_eq!(report.classes.iter().map(|c| c.count).sum::<usize>(), 0);
    assert!(report.summary[0].contains("no marks"));
}

// ── Clean, text-native ───────────────────────────────────────────────────────

#[test]
fn clean_a_marked_markdown_strips_the_mark_and_round_trips() {
    let marked = zero_width_marked();
    let outcome = clean_file(marked.as_bytes(), FileFormat::Markdown, &[MarkClass::ZeroWidth]).unwrap();

    assert!(outcome.altered);
    // The cleaned text (re-extracted from the written bytes) is the cover.
    assert_eq!(outcome.cleaned_text, COVER);
    // Proven by re-extraction: the written file carries no zero-width marks.
    let recheck = inspect_file(&outcome.bytes, FileFormat::Markdown).unwrap();
    assert_eq!(
        recheck.classes.iter().find(|c| c.id == "zero_width").unwrap().count,
        0
    );
}

#[test]
fn clean_a_marked_plain_text_preserves_a_utf8_bom() {
    let marked = zero_width_marked();
    let mut with_bom = vec![0xEF, 0xBB, 0xBF];
    with_bom.extend_from_slice(marked.as_bytes());

    let outcome = clean_file(&with_bom, FileFormat::PlainText, &[MarkClass::ZeroWidth]).unwrap();

    assert!(outcome.altered);
    assert_eq!(&outcome.bytes[..3], &[0xEF, 0xBB, 0xBF], "the BOM is preserved");
    assert_eq!(outcome.cleaned_text, COVER);
}

#[test]
fn clean_a_plain_markdown_changes_nothing_byte_for_byte() {
    let input = b"# Report\n\nNothing hidden here.\n";
    let outcome = clean_file(input, FileFormat::Markdown, &MarkClass::ALL).unwrap();

    assert!(!outcome.altered);
    assert_eq!(outcome.bytes, input, "a plain file is returned byte-for-byte");
}

// ── Clean, DOCX container ────────────────────────────────────────────────────

#[test]
fn clean_a_marked_docx_strips_invisible_marks_and_keeps_every_other_entry_byte_identical() {
    let (bytes, original_doc_xml) = marked_docx();
    let before = read_all_entries(&bytes);

    let outcome = clean_file(&bytes, FileFormat::Docx, &[MarkClass::ZeroWidth]).unwrap();
    assert!(outcome.altered);

    let after = read_all_entries(&outcome.bytes);

    // Every entry except the rewritten content part is byte-for-byte the same.
    assert_eq!(before.keys().collect::<Vec<_>>(), after.keys().collect::<Vec<_>>());
    for (name, content) in &before {
        if name == "word/document.xml" {
            continue;
        }
        assert_eq!(after.get(name), Some(content), "entry {name} must be untouched");
    }

    // The rewritten content part equals the original with exactly the zero-width
    // channel characters removed, and nothing else changed.
    let expected: String = original_doc_xml
        .chars()
        .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}'))
        .collect();
    assert_eq!(
        after.get("word/document.xml").unwrap(),
        expected.as_bytes(),
        "only the channel characters were removed from the content part"
    );
    assert_ne!(
        before.get("word/document.xml"),
        after.get("word/document.xml"),
        "the content part did change"
    );

    // And re-extraction proves the document no longer carries the mark.
    let recheck = inspect_file(&outcome.bytes, FileFormat::Docx).unwrap();
    assert_eq!(
        recheck.classes.iter().find(|c| c.id == "zero_width").unwrap().count,
        0
    );
}

#[test]
fn clean_a_docx_with_no_marks_returns_the_archive_untouched() {
    let doc_xml = marked_docx_document_xml(COVER); // COVER carries no marks
    let bytes = build_zip(&[
        ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
        ("word/document.xml", &doc_xml),
    ]);

    let outcome = clean_file(&bytes, FileFormat::Docx, &[MarkClass::ZeroWidth]).unwrap();
    assert!(!outcome.altered);
    assert_eq!(outcome.bytes, bytes, "an unmarked archive is returned byte-for-byte");
}

// ── Refusals by name ─────────────────────────────────────────────────────────

#[test]
fn cleaning_homoglyphs_in_a_docx_is_refused_by_name() {
    let (bytes, _) = marked_docx();
    let err = clean_file(&bytes, FileFormat::Docx, &[MarkClass::Homoglyph]).unwrap_err();
    match &err {
        TransformError::UnsupportedCombination { format, class, .. } => {
            assert_eq!(*format, "DOCX");
            assert!(class.to_lowercase().contains("look-alike"), "class named: {class}");
        }
        other => panic!("expected UnsupportedCombination, got {other:?}"),
    }
    // The message names the format and the operation.
    let msg = err.to_string();
    assert!(msg.contains("DOCX") && msg.contains("clean"), "message: {msg}");
}

#[test]
fn cleaning_an_html_document_is_refused_by_name() {
    let html = b"<html><body><p>Body with a mark.</p></body></html>";
    let err = clean_file(html, FileFormat::Html, &[MarkClass::ZeroWidth]).unwrap_err();
    match &err {
        TransformError::UnsupportedCombination { format, .. } => assert_eq!(*format, "HTML"),
        other => panic!("expected UnsupportedCombination, got {other:?}"),
    }
    assert!(err.to_string().contains("HTML"));
}

#[test]
fn inspecting_an_html_document_is_supported_even_though_cleaning_is_not() {
    // Inspect is read-only, so it works for HTML while clean refuses by name.
    let html = b"<html><body><h1>Heading</h1><p>Body text here.</p></body></html>";
    let report = inspect_file(html, FileFormat::Html).unwrap();
    assert_eq!(report.classes.len(), 4);
}

#[test]
fn cleaning_a_windows_1252_text_file_that_changes_is_refused_by_name() {
    // A file that is not valid UTF-8 (a lone 0xE9) falls back to Windows-1252.
    // The bytes E2 80 8B are the UTF-8 encoding of U+200B; read as cp1252 they
    // become the mojibake run the decoder's repair pass reconstructs back into a
    // zero-width space, so the extracted text carries a mark. Cleaning it would
    // need a re-encode to the lossy cp1252 target, which is refused by name.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"caf\xE9 ");
    bytes.extend_from_slice(&[0xE2, 0x80, 0x8B]);
    bytes.extend_from_slice(b"end");

    let err = clean_file(&bytes, FileFormat::PlainText, &[MarkClass::ZeroWidth]).unwrap_err();
    match &err {
        TransformError::UnsupportedEncoding { encoding, .. } => {
            assert!(encoding.contains("1252"), "encoding named: {encoding}");
        }
        other => panic!("expected UnsupportedEncoding, got {other:?}"),
    }
}

// ── Conceal, text-native ─────────────────────────────────────────────────────

/// The exact code line that must survive a conceal byte-for-byte.
const CODE_LINE: &str = "fn main() { println!(\"do not touch this code\"); }";

/// The exact inline equation that must survive a conceal byte-for-byte.
const EQUATION: &str = "$E = mc^2$";

/// A Markdown document with a fenced code block AND an inline equation, plus
/// enough prose that the zero-width carrier stays under the concealment density
/// ceiling. The prose is repeated so capacity never depends on a hand-counted
/// slot total: a larger cover only gives the carrier more room.
fn markdown_cover_with_code_and_equation() -> String {
    let prose =
        "The traceability workflow keeps every provenance record legible and auditable across \
         the whole editorial review. "
            .repeat(80);
    format!(
        "# Provenance Report\n\n{prose}\n\n```rust\n{CODE_LINE}\n```\n\nThe identity {EQUATION} \
         must render exactly as written.\n\n{prose}\n"
    )
}

#[test]
fn conceal_into_markdown_round_trips_and_the_secret_decodes() {
    let zw = ZeroWidth::new();
    let cover = markdown_cover_with_code_and_equation();
    let secret = "hello provenance";

    let outcome = conceal_file(cover.as_bytes(), FileFormat::Markdown, secret, &[&zw], None, false).unwrap();

    // The core actually placed the mark: the marked bytes differ from the cover
    // and are larger, and the sizes are measured, not asserted.
    assert_ne!(outcome.bytes, cover.as_bytes(), "the conceal must alter the document");
    assert_eq!(outcome.source_len, cover.len());
    assert_eq!(outcome.marked_len, outcome.bytes.len());
    assert_eq!(outcome.secret_len, secret.len());
    assert!(outcome.marked_len > outcome.source_len, "channel characters were added");
    assert_eq!(outcome.carriers, vec!["zero_width".to_string()]);
    assert!(outcome.cipher.is_none());

    // The secret decodes back from the marked file's own extracted text.
    let decoded = pipeline::decode(&outcome.marked_text, &[&zw], &[], None).unwrap();
    assert_eq!(decoded.hidden_data, secret.as_bytes());
    assert!(decoded.integrity_valid);
}

/// The point of the slice: a marked Markdown file keeps its code and its
/// equation byte-identical (placement protects both) and still round-trips.
#[test]
fn conceal_into_markdown_keeps_code_and_equation_byte_identical_and_round_trips() {
    let zw = ZeroWidth::new();
    let cover = markdown_cover_with_code_and_equation();
    let secret = "a concealed note";

    let outcome = conceal_file(cover.as_bytes(), FileFormat::Markdown, secret, &[&zw], None, false).unwrap();
    let marked = std::str::from_utf8(&outcome.bytes).expect("marked Markdown is valid UTF-8");

    // (a) The fenced code content and the equation survive byte-for-byte: no
    // channel character landed inside either protected region.
    assert!(
        marked.contains(CODE_LINE),
        "the fenced code block content was altered by the conceal"
    );
    assert!(
        marked.contains(EQUATION),
        "the inline equation was altered by the conceal"
    );

    // (b) The secret decodes back from the marked file.
    let decoded = pipeline::decode(&outcome.marked_text, &[&zw], &[], None).unwrap();
    assert_eq!(decoded.hidden_data, secret.as_bytes());
}

#[test]
fn conceal_into_plain_text_preserves_a_utf8_bom() {
    let zw = ZeroWidth::new();
    // A generous plain-text cover so the carrier stays under the ceiling.
    let cover = "Every record in the ledger is kept legible for the whole review team. ".repeat(80);
    let mut with_bom = vec![0xEF, 0xBB, 0xBF];
    with_bom.extend_from_slice(cover.as_bytes());

    let outcome = conceal_file(&with_bom, FileFormat::PlainText, "carry me", &[&zw], None, false).unwrap();

    assert_eq!(&outcome.bytes[..3], &[0xEF, 0xBB, 0xBF], "the BOM is preserved");
    let decoded = pipeline::decode(&outcome.marked_text, &[&zw], &[], None).unwrap();
    assert_eq!(decoded.hidden_data, b"carry me");
}

#[test]
fn conceal_with_a_cipher_and_passphrase_round_trips() {
    let zw = ZeroWidth::new();
    let cc = ChaCha20::new();
    let cover = markdown_cover_with_code_and_equation();
    let secret = "top secret";
    let passphrase = "a strong passphrase";

    let outcome = conceal_file(
        cover.as_bytes(),
        FileFormat::Markdown,
        secret,
        &[&zw],
        Some((&cc, passphrase)), false,)
    .unwrap();

    // The cipher actually applied is named in the outcome.
    assert_eq!(outcome.cipher.as_deref(), Some("chacha20_poly1305"));

    // Only the same passphrase recovers it.
    let decoded =
        pipeline::decode(&outcome.marked_text, &[&zw], &[&cc], Some(passphrase)).unwrap();
    assert_eq!(decoded.hidden_data, secret.as_bytes());
    assert_eq!(decoded.crypto_used.as_deref(), Some("chacha20_poly1305"));
}

// ── Conceal, refusals by name ────────────────────────────────────────────────

#[test]
fn concealing_into_a_docx_is_refused_by_name() {
    let (bytes, _) = marked_docx();
    let zw = ZeroWidth::new();
    let err = conceal_file(&bytes, FileFormat::Docx, "secret", &[&zw], None, false).unwrap_err();
    match &err {
        TransformError::UnsupportedConceal { format, .. } => assert_eq!(*format, "DOCX"),
        other => panic!("expected UnsupportedConceal, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(msg.contains("DOCX") && msg.contains("conceal"), "message: {msg}");
}

#[test]
fn concealing_into_an_html_document_is_refused_by_name() {
    let html = b"<html><body><p>Body text here to host a secret.</p></body></html>";
    let zw = ZeroWidth::new();
    let err = conceal_file(html, FileFormat::Html, "secret", &[&zw], None, false).unwrap_err();
    match &err {
        TransformError::UnsupportedConceal { format, .. } => assert_eq!(*format, "HTML"),
        other => panic!("expected UnsupportedConceal, got {other:?}"),
    }
    assert!(err.to_string().contains("HTML"));
}

#[test]
fn concealing_a_secret_too_large_for_the_cover_is_refused_by_named_arithmetic() {
    // A tiny cover cannot hold the secret under the Conceal density ceiling, so
    // the core refuses with named arithmetic rather than overflowing (invariant
    // 2, invariant 4b). It surfaces straight through as a Core refusal.
    let zw = ZeroWidth::new();
    let tiny_cover = b"A short note.";
    let big_secret = "this secret is far larger than such a tiny cover can ever conceal";

    let err = conceal_file(tiny_cover, FileFormat::Markdown, big_secret, &[&zw], None, false).unwrap_err();
    match &err {
        TransformError::Core(SteganoError::CapacityExceeded { needed, available }) => {
            assert!(
                needed > available,
                "the payload ({needed} bits) must exceed the concealment budget ({available} bits)"
            );
        }
        other => panic!("expected Core(CapacityExceeded), got {other:?}"),
    }
}

#[test]
fn concealing_an_empty_secret_is_refused_by_name() {
    let zw = ZeroWidth::new();
    let cover = markdown_cover_with_code_and_equation();
    let err = conceal_file(cover.as_bytes(), FileFormat::Markdown, "", &[&zw], None, false).unwrap_err();
    match &err {
        TransformError::Core(SteganoError::InvalidInput(reason)) => {
            assert!(reason.contains("hide"), "reason: {reason}");
        }
        other => panic!("expected Core(InvalidInput), got {other:?}"),
    }
}

#[test]
fn concealing_with_a_cipher_but_no_passphrase_is_refused_by_name() {
    // The core treats an empty passphrase as "no cipher", which would let a
    // secret the operator asked to encrypt travel in the clear. The file layer
    // refuses that by name (invariant 2).
    let zw = ZeroWidth::new();
    let cc = ChaCha20::new();
    let cover = markdown_cover_with_code_and_equation();

    let err = conceal_file(
        cover.as_bytes(),
        FileFormat::Markdown,
        "secret",
        &[&zw],
        Some((&cc, "")), false,)
    .unwrap_err();
    match &err {
        TransformError::MissingPassphrase { cipher } => {
            assert_eq!(cipher, "chacha20_poly1305");
        }
        other => panic!("expected MissingPassphrase, got {other:?}"),
    }
}
