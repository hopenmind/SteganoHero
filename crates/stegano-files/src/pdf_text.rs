//! PDF-to-text: read the TEXT LAYER of a PDF so the provenance and analysis
//! operations can act on it. This is EXTRACTION, never a render and never a mark
//! (invariant 4: conversion and reading are separate from marking).
//!
//! Pure Rust via `lopdf`, no Chromium. The only recorded reason PDF-to-text was
//! deferred was to avoid the 179 MB headless browser (see [`crate::pdf`], the PDF
//! EXPORT path); a small pure-Rust parser honours that reason, so reading a PDF's
//! text is now in reach.
//!
//! Honest contract (invariant 2, no silent degradation). Every failure names
//! itself; none returns empty or partial text as if it were the document:
//! - A PDF that cannot be parsed is refused by name.
//! - An encrypted PDF is refused by name (its text cannot be read without the
//!   password; this build does not attempt a password).
//! - A PDF with no extractable text layer (a scanned or image-only PDF) is
//!   refused by name rather than returned as an empty string.

use std::panic::{catch_unwind, AssertUnwindSafe};

use lopdf::Document;

/// An error from reading a PDF's text layer. Every variant names itself and its
/// context (invariant 2).
#[derive(Debug, thiserror::Error)]
pub enum PdfTextError {
    /// The bytes could not be parsed as a PDF, or the parser failed on a
    /// malformed structure.
    #[error("the PDF could not be parsed: {detail}")]
    Parse { detail: String },

    /// The PDF is encrypted. Its text cannot be read without the password, which
    /// this build does not attempt. Refused by name rather than returned garbled.
    #[error("the PDF is encrypted; its text cannot be read without the password, which this build does not attempt")]
    Encrypted,

    /// The PDF parsed but carries no extractable text layer: it is a scanned or
    /// image-only PDF. Refused by name rather than returned as an empty result.
    #[error("the PDF carries no extractable text layer (it looks like a scanned or image-only PDF); reading it as text is refused rather than returning an empty result")]
    NoTextLayer,
}

/// Extract the concatenated text layer of a PDF, page by page in page order. See
/// the module doc for the honest refusals.
pub fn extract_pdf_text(bytes: &[u8]) -> Result<String, PdfTextError> {
    let doc = Document::load_mem(bytes).map_err(|e| PdfTextError::Parse {
        detail: e.to_string(),
    })?;

    // An encrypted PDF carries an /Encrypt entry in its trailer. We do not attempt
    // a password, so reading its (encrypted) content streams would yield garbage.
    // Refuse by name (invariant 2).
    if doc.trailer.get(b"Encrypt").is_ok() {
        return Err(PdfTextError::Encrypted);
    }

    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(PdfTextError::NoTextLayer);
    }
    let page_numbers: Vec<u32> = pages.keys().copied().collect();

    // lopdf's text extraction has historically been able to panic on a malformed
    // content stream. A panic is worse than a named error (invariant 2), so it is
    // caught and turned into a parse refusal.
    let extracted = catch_unwind(AssertUnwindSafe(|| doc.extract_text(&page_numbers)))
        .map_err(|_| PdfTextError::Parse {
            detail: "the PDF text parser failed on a malformed content structure".to_string(),
        })?
        .map_err(|e| PdfTextError::Parse {
            detail: e.to_string(),
        })?;

    if extracted.trim().is_empty() {
        return Err(PdfTextError::NoTextLayer);
    }
    Ok(extracted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::content::{Content, Operation};
    use lopdf::{dictionary, Document, Object, Stream};

    /// Build a one-page PDF whose content stream draws `text` with a standard
    /// font, so a text extractor can read it back.
    fn pdf_with_text(text: &str) -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 24.into()]),
                Operation::new("Td", vec![72.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal(text)]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    /// Build a one-page PDF with an EMPTY content stream: it parses, but has no
    /// text to extract.
    fn pdf_without_text() -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content_id = doc.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn reads_the_text_layer_of_a_text_pdf() {
        let pdf = pdf_with_text("Hello provenance world");
        let text = extract_pdf_text(&pdf).expect("a text PDF yields its text");
        assert!(text.contains("Hello"), "extracted: {text:?}");
        assert!(text.contains("provenance"), "extracted: {text:?}");
    }

    #[test]
    fn a_pdf_with_no_text_layer_is_refused_by_name() {
        let pdf = pdf_without_text();
        let err = extract_pdf_text(&pdf).expect_err("an empty-text PDF is refused");
        assert!(matches!(err, PdfTextError::NoTextLayer), "got: {err}");
    }

    #[test]
    fn non_pdf_bytes_are_refused_by_name() {
        let err = extract_pdf_text(b"this is not a PDF at all").expect_err("garbage is refused");
        assert!(matches!(err, PdfTextError::Parse { .. }), "got: {err}");
    }

    #[test]
    fn extract_text_surfaces_a_pdf_as_lowered_text() {
        // The whole point of the slice: a PDF now flows through the file layer's
        // extract_text so inspect and analyze can act on it. It is classified
        // Lowered (a best-effort text rendering, not the source), so a lossless
        // write-back in PDF is refused elsewhere by name.
        let pdf = pdf_with_text("Traceable provenance body");
        let extracted =
            crate::extract_text(&pdf, crate::FileFormat::Pdf).expect("a text PDF extracts");
        assert!(extracted.text.contains("Traceable"), "text: {:?}", extracted.text);
        assert!(matches!(extracted.container, crate::Container::Lowered));
    }

    #[test]
    fn an_encrypted_pdf_is_refused_by_name() {
        // Build a valid PDF, then mark its trailer as encrypted the way a real
        // encrypted PDF declares it (an /Encrypt entry). The reader must refuse it
        // by name rather than read its content as if it were plain.
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        let encrypt_id = doc.add_object(dictionary! {
            "Filter" => "Standard",
            "V" => 1,
            "R" => 2,
        });
        doc.trailer.set("Root", catalog_id);
        doc.trailer.set("Encrypt", encrypt_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let err = extract_pdf_text(&buf).expect_err("an encrypted PDF is refused");
        assert!(matches!(err, PdfTextError::Encrypted), "got: {err}");
    }
}
