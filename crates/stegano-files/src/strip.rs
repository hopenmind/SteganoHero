//! SEC-STRIP: remove a file's metadata (its own native metadata and this tool's
//! added channel), leaving the document CONTENT byte-for-byte unchanged.
//!
//! This is the inverse of the additive metadata channel in [`crate::metadata`]:
//! where `embed_metadata` ADDS an entry and never touches content, this REMOVES
//! the metadata surfaces and never touches content. Removal, never editing: a
//! value is dropped, never rewritten to a chosen false one (editing would enable
//! forgery; removal is the clean document-sovereignty operation, like mat2).
//!
//! Per format:
//! - DOCX: drop every `docProps/*` entry (core, app, custom) and this tool's own
//!   channel entry; copy every other ZIP entry RAW, so the content is identical.
//! - ODT: drop `meta.xml` and this tool's channel entry; copy the rest RAW.
//! - PNG: drop the text (`tEXt`/`zTXt`/`iTXt`), EXIF (`eXIf`) and time (`tIME`)
//!   chunks; copy every other chunk (IHDR, IDAT, IEND, ...) verbatim, so the
//!   pixels are identical.
//! - SVG: drop every `<metadata>...</metadata>` element (native and this tool's
//!   own); leave the visible markup unchanged.
//! - JPEG: drop the APP1 (EXIF/XMP) and APP13 (IPTC/Photoshop) segments; copy
//!   every other segment and the scan data verbatim, so the image is identical.
//!
//! A format with no metadata surface here is refused BY NAME (invariant 2),
//! never returned unchanged as a silent no-op.

use std::io::Cursor;

use crate::metadata::DOCX_METADATA_ENTRY;
use crate::FileFormat;

const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

/// An error from the metadata strip. Every variant names the format and reason;
/// no path silently succeeds or returns the input unchanged (invariant 2).
#[derive(Debug, thiserror::Error)]
pub enum StripError {
    /// The format has no metadata surface this build can strip. Stripping serves
    /// DOCX, ODT, PNG, SVG and JPEG; any other format is refused BY NAME.
    #[error("the {format} format has no metadata surface to strip in this build; stripping serves docx, odt, png, svg and jpeg")]
    UnsupportedFormat { format: &'static str },

    /// The input is not a valid carrier of the declared format, so nothing could
    /// be stripped. Named rather than returning the input unchanged.
    #[error("cannot strip the {format} metadata: {detail}")]
    Carrier { format: &'static str, detail: String },
}

/// Remove the metadata surfaces of `bytes` (a document of `format`) and return
/// the new file bytes, with the document CONTENT byte-for-byte unchanged.
///
/// Supported: DOCX, ODT, PNG, SVG, JPEG. Any other format is refused by name.
pub fn strip_metadata(bytes: &[u8], format: FileFormat) -> Result<Vec<u8>, StripError> {
    match format {
        FileFormat::Docx | FileFormat::Odt => strip_zip(bytes, format),
        FileFormat::Png => strip_png(bytes),
        FileFormat::Svg => strip_svg(bytes),
        FileFormat::Jpeg => strip_jpeg(bytes),
        other => Err(StripError::UnsupportedFormat {
            format: other.name(),
        }),
    }
}

// ── DOCX / ODT: drop the metadata ZIP entries, copy the rest raw ───────────────

fn is_zip_metadata_entry(name: &str, format: FileFormat) -> bool {
    if name == DOCX_METADATA_ENTRY {
        return true;
    }
    match format {
        FileFormat::Docx => name.starts_with("docProps/"),
        FileFormat::Odt => name == "meta.xml",
        _ => false,
    }
}

fn strip_zip(bytes: &[u8], format: FileFormat) -> Result<Vec<u8>, StripError> {
    let fname = format.name();
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| StripError::Carrier {
        format: fname,
        detail: format!("not a valid {fname}/ZIP container: {e}"),
    })?;

    let mut out = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(Cursor::new(&mut out));
        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i).map_err(|e| StripError::Carrier {
                format: fname,
                detail: format!("cannot read archive entry {i}: {e}"),
            })?;
            if is_zip_metadata_entry(entry.name(), format) {
                continue;
            }
            // Raw copy: the compressed bytes and per-entry headers are preserved,
            // so each surviving entry is byte-identical.
            writer.raw_copy_file(entry).map_err(|e| StripError::Carrier {
                format: fname,
                detail: format!("cannot copy an archive entry: {e}"),
            })?;
        }
        writer.finish().map_err(|e| StripError::Carrier {
            format: fname,
            detail: format!("cannot finalize the archive: {e}"),
        })?;
    }
    Ok(out)
}

// ── PNG: drop the metadata chunks, copy the rest verbatim ─────────────────────

fn is_png_metadata_chunk(chunk_type: &[u8]) -> bool {
    matches!(chunk_type, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME")
}

fn strip_png(png: &[u8]) -> Result<Vec<u8>, StripError> {
    if png.len() < 8 || &png[..8] != PNG_SIG {
        return Err(StripError::Carrier {
            format: "png",
            detail: "not a valid PNG (bad signature)".to_string(),
        });
    }
    let mut out = Vec::with_capacity(png.len());
    out.extend_from_slice(&png[..8]);

    let mut pos = 8usize;
    loop {
        if pos + 8 > png.len() {
            break;
        }
        let length = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
        let chunk_type = &png[pos + 4..pos + 8];
        // length(4) + type(4) + data(length) + crc(4)
        let chunk_end = match pos.checked_add(12).and_then(|v| v.checked_add(length)) {
            Some(end) if end <= png.len() => end,
            _ => break, // truncated: stop before the malformed chunk
        };
        let is_iend = chunk_type == b"IEND";
        if !is_png_metadata_chunk(chunk_type) {
            out.extend_from_slice(&png[pos..chunk_end]);
        }
        pos = chunk_end;
        if is_iend {
            break;
        }
    }
    Ok(out)
}

// ── SVG: drop every <metadata> element, keep the visible markup ───────────────

/// True when the character at byte `idx` is not part of a longer element name,
/// so `<metadata` there is the element and not a look-alike like `<metadatax`.
fn is_tag_boundary(bytes: &[u8], idx: usize) -> bool {
    match bytes.get(idx) {
        None => true,
        Some(&b) => b == b'>' || b == b'/' || b.is_ascii_whitespace(),
    }
}

fn strip_svg(svg_bytes: &[u8]) -> Result<Vec<u8>, StripError> {
    let svg = std::str::from_utf8(svg_bytes).map_err(|_| StripError::Carrier {
        format: "svg",
        detail: "SVG is not valid UTF-8".to_string(),
    })?;
    let lower = svg.to_ascii_lowercase();
    let bytes = svg.as_bytes();

    let mut out = String::with_capacity(svg.len());
    let mut cursor = 0usize;
    let mut search = 0usize;
    while let Some(rel) = lower[search..].find("<metadata") {
        let start = search + rel;
        // Guard against look-alikes (<metadatax...): the char after the name must
        // be a tag boundary.
        if !is_tag_boundary(bytes, start + "<metadata".len()) {
            search = start + "<metadata".len();
            continue;
        }
        // End of the opening tag.
        let tag_open_end = match svg[start..].find('>') {
            Some(p) => start + p + 1,
            None => break, // unterminated tag; leave the tail untouched
        };
        // Copy everything up to this element.
        out.push_str(&svg[cursor..start]);

        if svg[start..tag_open_end].trim_end().ends_with("/>") {
            // Self-closing <metadata .../>: drop just the tag.
            cursor = tag_open_end;
            search = tag_open_end;
        } else {
            // Paired: drop through the matching </metadata>.
            match lower[tag_open_end..].find("</metadata>") {
                Some(crel) => {
                    let close_end = tag_open_end + crel + "</metadata>".len();
                    cursor = close_end;
                    search = close_end;
                }
                None => {
                    // No close: drop the rest of the document from here.
                    cursor = svg.len();
                    search = svg.len();
                }
            }
        }
    }
    out.push_str(&svg[cursor..]);
    Ok(out.into_bytes())
}

// ── JPEG: drop the APP1 (EXIF/XMP) and APP13 (IPTC) segments ──────────────────

fn strip_jpeg(jpeg: &[u8]) -> Result<Vec<u8>, StripError> {
    if jpeg.len() < 2 || jpeg[0] != 0xFF || jpeg[1] != 0xD8 {
        return Err(StripError::Carrier {
            format: "jpeg",
            detail: "not a valid JPEG (missing the SOI marker)".to_string(),
        });
    }
    let mut out = Vec::with_capacity(jpeg.len());
    out.extend_from_slice(&jpeg[..2]); // SOI

    let mut pos = 2usize;
    loop {
        if pos + 2 > jpeg.len() || jpeg[pos] != 0xFF {
            out.extend_from_slice(&jpeg[pos..]);
            break;
        }
        let marker = jpeg[pos + 1];
        // Start of scan: the entropy-coded data follows and runs to EOI. Copy the
        // rest verbatim, so the image is byte-identical.
        if marker == 0xDA {
            out.extend_from_slice(&jpeg[pos..]);
            break;
        }
        // Standalone markers carry no length field.
        if marker == 0xD9 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            out.extend_from_slice(&jpeg[pos..pos + 2]);
            pos += 2;
            continue;
        }
        if pos + 4 > jpeg.len() {
            out.extend_from_slice(&jpeg[pos..]);
            break;
        }
        let length = u16::from_be_bytes([jpeg[pos + 2], jpeg[pos + 3]]) as usize;
        // marker(2) + length field (which counts itself and the data)
        let seg_end = match pos.checked_add(2).and_then(|v| v.checked_add(length)) {
            Some(end) if end <= jpeg.len() => end,
            _ => {
                out.extend_from_slice(&jpeg[pos..]);
                break;
            }
        };
        // APP1 (EXIF/XMP) and APP13 (IPTC/Photoshop) are metadata: drop them.
        if marker != 0xE1 && marker != 0xED {
            out.extend_from_slice(&jpeg[pos..seg_end]);
        }
        pos = seg_end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_svg_removes_metadata_and_keeps_markup() {
        let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><metadata><rdf>author</rdf></metadata><rect width=\"10\" height=\"10\"/></svg>";
        let out = String::from_utf8(strip_svg(svg.as_bytes()).unwrap()).unwrap();
        assert!(!out.contains("<metadata"));
        assert!(!out.contains("author"));
        assert!(out.contains("<rect width=\"10\" height=\"10\"/>"));
        assert!(out.starts_with("<svg"));
    }

    #[test]
    fn strip_svg_handles_self_closing_and_lookalikes() {
        let svg = "<svg><metadata/><metadatax>keep</metadatax><g/></svg>";
        let out = String::from_utf8(strip_svg(svg.as_bytes()).unwrap()).unwrap();
        assert!(!out.contains("<metadata/>"));
        assert!(out.contains("<metadatax>keep</metadatax>"), "a look-alike element is not touched: {out}");
    }

    #[test]
    fn an_unsupported_format_is_refused_by_name() {
        let error = strip_metadata(b"plain text", FileFormat::PlainText).unwrap_err();
        assert!(matches!(error, StripError::UnsupportedFormat { .. }));
    }
}
