//! Pure write-back primitives for the file layer.
//!
//! Three self-contained tools, none of which knows anything about marks or the
//! steganography core (correct layering: the transform module supplies the
//! per-node operation, this module only moves bytes faithfully):
//!
//! 1. [`rewrite_text_nodes`] — a surgical XML rewrite that applies a caller's
//!    transform to each character-data node and leaves every other byte (tags,
//!    attributes, comments, whitespace) exactly as it was.
//! 2. [`repackage_zip`] — rebuild a ZIP archive with one entry rewritten and
//!    every other entry copied verbatim (compressed bytes and metadata intact).
//! 3. Text-encoding detection and re-encoding for the text-native formats, so a
//!    cleaned document keeps the encoding and BOM it arrived with.

use std::io::{Cursor, Write};

use quick_xml::events::Event;
use quick_xml::reader::Reader;

// ── Surgical XML text-node rewrite ───────────────────────────────────────────

/// Rewrite only the character data of an XML document, applying `transform` to
/// each text (and CDATA) node's raw source slice and splicing the result back
/// into the original bytes.
///
/// Every tag, attribute, comment, processing instruction, XML declaration and
/// whitespace byte outside a character-data node is preserved exactly; a node
/// whose transform is a no-op is left byte-identical (only changed nodes are
/// spliced). The result is therefore the original document with the transform
/// applied to its text and nothing else.
///
/// `transform` receives the raw, still-escaped source slice of the node (for a
/// text node, the bytes between the enclosing tags; for CDATA, the whole
/// `<![CDATA[...]]>` run). The intended transform only deletes specific
/// invisible Unicode code points, so it never disturbs entity references
/// (`&amp;`) or the CDATA markers, which are ASCII.
pub(crate) fn rewrite_text_nodes<F>(xml: &str, transform: F) -> Result<String, String>
where
    F: Fn(&str) -> String,
{
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false; // lenient, matching the extractors

    let mut out = String::with_capacity(xml.len());
    let mut copied = 0usize; // bytes of `xml` already emitted to `out`

    loop {
        // `buffer_position` before the read is the start of the event about to
        // be read; after the read it is the end of that event. Every byte of an
        // XML document belongs to exactly one event, so these spans are
        // contiguous and the untouched bytes copy across exactly.
        let start = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|e| format!("XML rewrite failed: {}", e))?;
        let end = reader.buffer_position() as usize;

        match event {
            Event::Eof => break,
            Event::Text(_) | Event::CData(_) => {
                let raw = &xml[start..end];
                let replaced = transform(raw);
                if replaced != raw {
                    out.push_str(&xml[copied..start]);
                    out.push_str(&replaced);
                    copied = end;
                }
            }
            _ => {}
        }
    }

    out.push_str(&xml[copied..]);
    Ok(out)
}

// ── ZIP repackaging ──────────────────────────────────────────────────────────

/// Rebuild a ZIP archive with a single entry's content replaced and every other
/// entry copied verbatim.
///
/// The rewritten entry is written fresh with the same compression method it had.
/// Every other entry is transferred with `raw_copy_file`, which copies its
/// compressed data and metadata byte-for-byte, so the resulting archive differs
/// from the original in exactly one entry and nowhere else.
pub(crate) fn repackage_zip(
    archive_bytes: &[u8],
    entry: &str,
    new_content: &str,
) -> Result<Vec<u8>, String> {
    use zip::write::SimpleFileOptions;

    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|e| format!("reopen archive: {}", e))?;

    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(Cursor::new(&mut buf));
        let mut found = false;

        for i in 0..archive.len() {
            // Peek the name and compression method under a scoped borrow.
            let (name, method) = {
                let file = archive
                    .by_index_raw(i)
                    .map_err(|e| format!("read entry {i}: {}", e))?;
                (file.name().to_string(), file.compression())
            };

            if name == entry {
                found = true;
                let options = SimpleFileOptions::default().compression_method(method);
                writer
                    .start_file(name, options)
                    .map_err(|e| format!("start rewritten entry: {}", e))?;
                writer
                    .write_all(new_content.as_bytes())
                    .map_err(|e| format!("write rewritten entry: {}", e))?;
            } else {
                let file = archive
                    .by_index_raw(i)
                    .map_err(|e| format!("raw read entry {i}: {}", e))?;
                writer
                    .raw_copy_file(file)
                    .map_err(|e| format!("copy entry {name}: {}", e))?;
            }
        }

        if !found {
            return Err(format!("entry {entry} not found in archive"));
        }

        writer
            .finish()
            .map_err(|e| format!("finish archive: {}", e))?;
    }

    Ok(buf)
}

// ── Text-encoding detection and re-encoding ──────────────────────────────────

/// The byte encoding a text file arrived in, mirroring the decode order in
/// [`crate::text_encoding::decode_bytes`], so write-back can preserve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextEncoding {
    /// UTF-8, with or without a leading byte-order mark.
    Utf8 { bom: bool },
    /// UTF-16, little-endian, with a BOM.
    Utf16Le,
    /// UTF-16, big-endian, with a BOM.
    Utf16Be,
    /// Not valid UTF-8 and no BOM: the decoder fell back to Windows-1252. Re-
    /// encoding arbitrary Unicode to this legacy target is lossy, so write-back
    /// of a changed document refuses it by name rather than degrade.
    Cp1252Fallback,
}

/// Classify the encoding of raw bytes, in the same order the decoder honours it.
pub(crate) fn detect_text_encoding(bytes: &[u8]) -> TextEncoding {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        TextEncoding::Utf8 { bom: true }
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        TextEncoding::Utf16Le
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        TextEncoding::Utf16Be
    } else if std::str::from_utf8(bytes).is_ok() {
        TextEncoding::Utf8 { bom: false }
    } else {
        TextEncoding::Cp1252Fallback
    }
}

/// Re-encode `text` in `encoding`, preserving its BOM.
///
/// Returns `None` for [`TextEncoding::Cp1252Fallback`], whose re-encoding of
/// arbitrary Unicode is a lossy target; the caller turns that into a named
/// refusal instead of writing a degraded file.
pub(crate) fn encode_text(text: &str, encoding: TextEncoding) -> Option<Vec<u8>> {
    match encoding {
        TextEncoding::Utf8 { bom } => {
            let mut out = Vec::with_capacity(text.len() + if bom { 3 } else { 0 });
            if bom {
                out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            }
            out.extend_from_slice(text.as_bytes());
            Some(out)
        }
        TextEncoding::Utf16Le => {
            let mut out = vec![0xFF, 0xFE];
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            Some(out)
        }
        TextEncoding::Utf16Be => {
            let mut out = vec![0xFE, 0xFF];
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_be_bytes());
            }
            Some(out)
        }
        TextEncoding::Cp1252Fallback => None,
    }
}

/// A stable, human-readable label for an encoding, for error messages.
pub(crate) fn encoding_label(encoding: TextEncoding) -> &'static str {
    match encoding {
        TextEncoding::Utf8 { bom: true } => "UTF-8 (with BOM)",
        TextEncoding::Utf8 { bom: false } => "UTF-8",
        TextEncoding::Utf16Le => "UTF-16 LE",
        TextEncoding::Utf16Be => "UTF-16 BE",
        TextEncoding::Cp1252Fallback => "Windows-1252 (non-Unicode)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_touches_only_changed_text_nodes() {
        // Remove the zero-width space (U+200B) from text nodes; leave tags,
        // attributes, entities and whitespace exactly as they were.
        let xml = "<a x=\"1\">he\u{200B}llo</a>\n<b>a &amp; b</b>";
        let out = rewrite_text_nodes(xml, |raw| raw.replace('\u{200B}', "")).unwrap();
        assert_eq!(out, "<a x=\"1\">hello</a>\n<b>a &amp; b</b>");
    }

    #[test]
    fn rewrite_with_a_noop_transform_returns_the_input_verbatim() {
        let xml = "<w:p><w:r><w:t>unchanged</w:t></w:r></w:p>";
        let out = rewrite_text_nodes(xml, |raw| raw.to_string()).unwrap();
        assert_eq!(out, xml);
    }

    #[test]
    fn detect_maps_each_byte_prefix_to_its_encoding() {
        assert_eq!(
            detect_text_encoding(&[0xEF, 0xBB, 0xBF, b'a']),
            TextEncoding::Utf8 { bom: true }
        );
        assert_eq!(detect_text_encoding(b"plain"), TextEncoding::Utf8 { bom: false });
        assert_eq!(detect_text_encoding(&[0xFF, 0xFE, b'a', 0]), TextEncoding::Utf16Le);
        assert_eq!(detect_text_encoding(&[0xFE, 0xFF, 0, b'a']), TextEncoding::Utf16Be);
        // A lone 0xE9 with no valid continuation is not UTF-8.
        assert_eq!(detect_text_encoding(&[b'a', 0xE9, b'b']), TextEncoding::Cp1252Fallback);
    }

    #[test]
    fn encode_preserves_utf8_bom_and_refuses_the_lossy_target() {
        assert_eq!(
            encode_text("hi", TextEncoding::Utf8 { bom: true }).unwrap(),
            vec![0xEF, 0xBB, 0xBF, b'h', b'i']
        );
        assert_eq!(
            encode_text("hi", TextEncoding::Utf8 { bom: false }).unwrap(),
            b"hi".to_vec()
        );
        assert!(encode_text("anything", TextEncoding::Cp1252Fallback).is_none());
    }

    #[test]
    fn utf16_round_trips_through_the_decoder() {
        for encoding in [TextEncoding::Utf16Le, TextEncoding::Utf16Be] {
            let text = "caf\u{E9} \u{2014} test";
            let bytes = encode_text(text, encoding).unwrap();
            assert_eq!(crate::text_encoding::decode_bytes(&bytes), text);
        }
    }
}
