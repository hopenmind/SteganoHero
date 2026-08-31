//! ZIP-container text extraction for the Office formats (DOCX, ODT).
//!
//! Provenance of the ZIP plumbing and the entry names: the upstream converter
//! project, `crates/core/src/import.rs` (`docx_generic_to_md`, `odt_to_md`),
//! adapted from path input to in-memory `&[u8]` so the file layer can operate on
//! bytes the surfaces already hold.
//!
//! Difference from the upstream converter: where that tree falls back to a legacy string
//! scanner on a parser miss, this layer raises by name instead (invariant 2, no
//! silent degradation). The namespace-aware parser is the single path.

use std::io::{Cursor, Read};

use crate::office_xml;

/// Hard cap on bytes read from any single ZIP archive entry (zip-bomb guard).
/// 128 MiB is far above any legitimate document part.
const MAX_ZIP_ENTRY_BYTES: u64 = 128 << 20;

/// The text extracted from a ZIP-based document, plus the primary content part
/// retained verbatim for a later surgical write-back slice.
pub(crate) struct ZipExtract {
    pub text: String,
    /// Archive path of the primary content part (e.g. `word/document.xml`).
    pub entry: String,
    /// Raw XML of that part, as read from the archive.
    pub xml: String,
}

/// Extract text from DOCX bytes: read `word/document.xml` (+ optional rels for
/// hyperlink targets), parse it namespace-aware. Raises by name on any failure.
pub(crate) fn extract_docx(bytes: &[u8]) -> Result<ZipExtract, String> {
    let mut z = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("DOCX ZIP error: {}", e))?;
    let mut xml = String::new();
    z.by_name("word/document.xml")
        .map_err(|_| "DOCX: word/document.xml not found".to_string())?
        .take(MAX_ZIP_ENTRY_BYTES)
        .read_to_string(&mut xml)
        .map_err(|e| format!("DOCX: word/document.xml not UTF-8: {}", e))?;

    // Hyperlink targets (optional): absence is not an error.
    let mut rels_xml = String::new();
    if let Ok(r) = z.by_name("word/_rels/document.xml.rels") {
        let _ = r.take(MAX_ZIP_ENTRY_BYTES).read_to_string(&mut rels_xml);
    }
    let rels = office_xml::parse_docx_rels(&rels_xml);

    let text = office_xml::docx_document_to_md(&xml, &rels)?;
    Ok(ZipExtract { text, entry: "word/document.xml".into(), xml })
}

/// Extract text from ODT bytes: read `content.xml`, parse it namespace-aware.
/// Raises by name on any failure.
pub(crate) fn extract_odt(bytes: &[u8]) -> Result<ZipExtract, String> {
    let mut z = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("ODT ZIP error: {}", e))?;
    let mut xml = String::new();
    z.by_name("content.xml")
        .map_err(|_| "ODT: content.xml not found".to_string())?
        .take(MAX_ZIP_ENTRY_BYTES)
        .read_to_string(&mut xml)
        .map_err(|e| format!("ODT: content.xml not UTF-8: {}", e))?;

    let text = office_xml::odt_content_to_md(&xml)?;
    Ok(ZipExtract { text, entry: "content.xml".into(), xml })
}
