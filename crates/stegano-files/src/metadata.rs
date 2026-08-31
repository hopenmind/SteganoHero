//! # Metadata channel: the zero-loss ADDITIVE provenance route
//!
//! This is the standalone, engine-level metadata channel. It writes an arbitrary
//! payload into a file's metadata surface and recovers it, leaving the document's
//! CONTENT byte-for-byte unchanged. That is the whole point of metadata
//! injection: it is additive and zero-loss by construction (add a metadata
//! entry, never touch the document content), the ADDITIVE counterpart to the
//! in-band marking route.
//!
//! It serves three surfaces, all pure Rust, no external process, no network. The
//! carrier primitives (PNG `tEXt`, SVG `<metadata>`) and their markers are owned
//! HERE, under SteganoHero-owned, technique-neutral names (invariant 8), so an
//! emitted file names only this project.
//!
//! - **DOCX**: a custom ZIP entry ([`DOCX_METADATA_ENTRY`]). Every other archive
//!   entry is copied raw (compressed bytes and metadata preserved), so the
//!   document content is byte-identical and only the new entry is added.
//! - **PNG**: a `tEXt` ancillary chunk inserted right after IHDR, with a correct
//!   hand-written CRC-32, keyed by [`PNG_METADATA_KEYWORD`]. The pixel data
//!   (IDAT) is untouched.
//! - **SVG**: a `<metadata>` element (in the [`SVG_NS_URI`] namespace) inserted as
//!   the first child of the root `<svg>`. The visible markup is untouched.
//!
//! ## Payload-agnostic
//!
//! The payload is arbitrary bytes. XML text (DOCX entry, SVG CDATA) cannot carry
//! most control bytes, and PNG `tEXt` is a Latin-1 text field, so the payload is
//! base64-encoded before it rides any carrier and decoded on recovery. base64 is
//! ASCII, valid in all three surfaces, and contains no `]]>`, so a binary payload
//! (including NUL and non-UTF-8 bytes) round-trips exactly with no CDATA escaping.
//! The base64 codec is hand-ported here (a few dozen lines, pure Rust) rather
//! than pulling a new dependency.
//!
//! ## Honest failures (invariant 2)
//!
//! A format with no metadata channel here is refused BY NAME
//! ([`MetadataError::UnsupportedFormat`]), never a silent no-op. A PNG writer that
//! returned its input unchanged on a non-PNG would be exactly the silent
//! degradation this channel forbids, so [`embed_metadata`] validates the carrier
//! first and raises [`MetadataError::Carrier`] instead. [`recover_metadata`]
//! returns `Ok(None)` for an absent channel (not an error) and an `Err` only when
//! the channel is present but its payload cannot be decoded
//! ([`MetadataError::Unreadable`]).
//!
//! ## Not wired to the provenance binding yet
//!
//! This slice is the standalone engine-level channel only. The
//! `provenance::Binding` trait is text-oriented (`bind(cover: &str)`); a
//! bytes-oriented format-metadata binding is a separate design decision and a
//! later slice.

use std::io::{Cursor, Read, Write};

use crate::FileFormat;

/// The ZIP entry name this channel uses for the DOCX metadata payload. It is a
/// SteganoHero-owned name, so a DOCX this channel writes carries no other
/// project's entry. Word and other readers ignore an entry they do not know.
pub const DOCX_METADATA_ENTRY: &str = "steganohero-metadata.b64";

/// PNG `tEXt` chunk keyword for this channel. A SteganoHero-owned, neutral,
/// technique-free marker (invariant 8): a single stable product keyword, with no
/// method or technique word. Well within the PNG spec's 79-character keyword cap.
/// An emitted PNG names only this project.
pub const PNG_METADATA_KEYWORD: &[u8] = b"steganohero";

/// PNG file signature (8 bytes), so the carrier can be validated before the write
/// (invariant 2).
const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";

/// SVG metadata namespace URI: a SteganoHero-owned, neutral, technique-free
/// identifier (invariant 8). The channel builds and reads the `<metadata>` element
/// itself (see [`embed_svg`] / [`recover_svg`]).
pub const SVG_NS_URI: &str = "https://hopenmind.com/steganohero/ns#";

/// SVG namespace prefix for the metadata element (`<sh:...>`).
const SVG_NS_PREFIX: &str = "sh";

/// SVG element name carrying the payload inside `<metadata>`. Neutral and
/// technique-free (invariant 8): no method name, no "latex", "mark" or "stego".
const SVG_PAYLOAD_TAG: &str = "payload";

/// Hard cap on bytes read from a single ZIP entry (zip-bomb guard), matching the
/// rest of this crate. 128 MiB is far above any legitimate metadata payload.
const MAX_ZIP_ENTRY_BYTES: u64 = 128 << 20;

/// An error from the standalone metadata channel. Every variant names the format
/// and the reason; no path silently succeeds or returns empty (invariant 2).
#[derive(Debug, thiserror::Error)]
pub enum MetadataError {
    /// The format has no metadata channel in this build. Only DOCX, PNG and SVG
    /// carry one; every other format is refused BY NAME rather than treated as a
    /// no-op (invariant 2).
    #[error("the {format} format has no metadata channel in this build; only docx, png and svg carry one")]
    UnsupportedFormat { format: &'static str },

    /// The input bytes are not a valid carrier of the declared format, so no
    /// metadata could be written. Named rather than returning the input unchanged
    /// (invariant 2: no silent degradation).
    #[error("cannot write the {format} metadata channel: {detail}")]
    Carrier { format: &'static str, detail: String },

    /// The metadata channel is present but its stored payload could not be
    /// decoded (corrupt base64, a malformed entry, or an unreadable container).
    /// An ABSENT channel is not an error; it returns `Ok(None)`. This is only for
    /// a present-but-unreadable one.
    #[error("the {format} metadata channel is present but unreadable: {detail}")]
    Unreadable { format: &'static str, detail: String },

    /// The format has no NATIVE metadata reader in this build. Distinct from the
    /// embed channel above: native reading (a format's OWN standard metadata,
    /// e.g. Office docProps) currently serves DOCX and ODT. Every other format is
    /// refused BY NAME rather than returned empty (invariant 2). See
    /// [`crate::read_native_metadata`].
    #[error("the {format} format has no native metadata reader in this build; native reading currently serves docx and odt")]
    NoNativeMetadata { format: &'static str },

    /// A native metadata part was present but could not be read: an unreadable
    /// container, a part that is not valid text, or malformed docProps XML. Named
    /// rather than returned partial or empty (invariant 2). An ABSENT part (no
    /// `docProps/core.xml`, no `meta.xml`) is NOT this error: it yields an
    /// empty-but-explicit result. Also raised by the image-metadata reader for a
    /// non-image byte stream, a truncated container, or a malformed EXIF block.
    #[error("the {format} native metadata is unreadable: {detail}")]
    NativeUnreadable { format: &'static str, detail: String },

    /// The format has no IMAGE-metadata (EXIF/XMP) reader in this build. Distinct
    /// from the Office docProps reader above: image reading serves JPEG, TIFF, PNG
    /// and WebP. Every other format is refused BY NAME rather than returned empty
    /// (invariant 2). See [`crate::read_image_metadata`].
    #[error("the {format} format has no image-metadata reader in this build; image-metadata reading serves jpeg, tiff, png and webp")]
    NoImageMetadata { format: &'static str },
}

/// Write `payload` into the metadata channel of `bytes` (a document of `format`)
/// and return the new file bytes, with the document CONTENT byte-for-byte
/// unchanged. This is the additive, zero-loss provenance route.
///
/// Supported formats: DOCX, PNG, SVG. Any other format is refused by name.
pub fn embed_metadata(
    bytes: &[u8],
    format: FileFormat,
    payload: &[u8],
) -> Result<Vec<u8>, MetadataError> {
    match format {
        FileFormat::Docx => embed_docx(bytes, payload),
        FileFormat::Png => embed_png(bytes, payload),
        FileFormat::Svg => embed_svg(bytes, payload),
        other => Err(MetadataError::UnsupportedFormat { format: other.name() }),
    }
}

/// Recover the payload written by [`embed_metadata`] from `bytes` (a document of
/// `format`). Returns `Ok(Some(payload))` when present, `Ok(None)` when the
/// channel is absent (not an error), and `Err` only when the channel is present
/// but its payload cannot be decoded.
///
/// Supported formats: DOCX, PNG, SVG. Any other format is refused by name.
pub fn recover_metadata(
    bytes: &[u8],
    format: FileFormat,
) -> Result<Option<Vec<u8>>, MetadataError> {
    match format {
        FileFormat::Docx => recover_docx(bytes),
        FileFormat::Png => recover_png(bytes),
        FileFormat::Svg => recover_svg(bytes),
        other => Err(MetadataError::UnsupportedFormat { format: other.name() }),
    }
}

// ── DOCX: custom ZIP entry ────────────────────────────────────────────────────

fn embed_docx(docx: &[u8], payload: &[u8]) -> Result<Vec<u8>, MetadataError> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(docx)).map_err(|e| MetadataError::Carrier {
            format: "docx",
            detail: format!("not a valid DOCX/ZIP container: {e}"),
        })?;

    let mut out_buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(Cursor::new(&mut out_buf));

        // Copy every existing entry RAW: the compressed bytes and per-entry
        // metadata (name, method, CRC, sizes) are preserved, so each entry is
        // byte-identical. Any prior metadata entry is dropped, so a re-embed
        // REPLACES rather than duplicates the channel.
        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i).map_err(|e| MetadataError::Carrier {
                format: "docx",
                detail: format!("cannot read archive entry {i}: {e}"),
            })?;
            if entry.name() == DOCX_METADATA_ENTRY {
                continue;
            }
            writer.raw_copy_file(entry).map_err(|e| MetadataError::Carrier {
                format: "docx",
                detail: format!("cannot copy an archive entry: {e}"),
            })?;
        }

        // Add the metadata entry: the base64 payload, stored uncompressed.
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file(DOCX_METADATA_ENTRY, options)
            .map_err(|e| MetadataError::Carrier {
                format: "docx",
                detail: format!("cannot start the metadata entry: {e}"),
            })?;
        writer
            .write_all(base64_encode(payload).as_bytes())
            .map_err(|e| MetadataError::Carrier {
                format: "docx",
                detail: format!("cannot write the metadata entry: {e}"),
            })?;
        writer.finish().map_err(|e| MetadataError::Carrier {
            format: "docx",
            detail: format!("cannot finalize the archive: {e}"),
        })?;
    }
    Ok(out_buf)
}

fn recover_docx(docx: &[u8]) -> Result<Option<Vec<u8>>, MetadataError> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(docx)).map_err(|e| MetadataError::Unreadable {
            format: "docx",
            detail: format!("not a valid DOCX/ZIP container: {e}"),
        })?;

    let entry = match archive.by_name(DOCX_METADATA_ENTRY) {
        Ok(entry) => entry,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => {
            return Err(MetadataError::Unreadable {
                format: "docx",
                detail: format!("cannot open the metadata entry: {e}"),
            })
        }
    };

    let mut encoded = String::new();
    entry
        .take(MAX_ZIP_ENTRY_BYTES)
        .read_to_string(&mut encoded)
        .map_err(|e| MetadataError::Unreadable {
            format: "docx",
            detail: format!("the metadata entry is not valid text: {e}"),
        })?;

    base64_decode(&encoded)
        .map(Some)
        .map_err(|detail| MetadataError::Unreadable { format: "docx", detail })
}

// ── PNG: tEXt chunk (channel-owned carrier) ───────────────────────────────────

fn embed_png(png: &[u8], payload: &[u8]) -> Result<Vec<u8>, MetadataError> {
    // A PNG writer that returned its input unchanged on invalid bytes would be
    // the silent degradation invariant 2 forbids, so validate the carrier here
    // and raise by name before writing.
    if png.len() < 33 || &png[..8] != PNG_SIG {
        return Err(MetadataError::Carrier {
            format: "png",
            detail: "not a valid PNG (bad signature or truncated before IHDR)".to_string(),
        });
    }

    let out = write_png_text_chunk(png, PNG_METADATA_KEYWORD, base64_encode(payload).as_bytes());

    // Defensive: a valid PNG must have grown by the tEXt chunk. If it did not,
    // the write was a no-op and we refuse rather than hand back the input.
    if out.len() <= png.len() {
        return Err(MetadataError::Carrier {
            format: "png",
            detail: "the metadata chunk was not written".to_string(),
        });
    }
    Ok(out)
}

fn recover_png(png: &[u8]) -> Result<Option<Vec<u8>>, MetadataError> {
    match read_png_text_chunk(png, PNG_METADATA_KEYWORD) {
        None => Ok(None),
        Some(encoded) => base64_decode(&encoded)
            .map(Some)
            .map_err(|detail| MetadataError::Unreadable { format: "png", detail }),
    }
}

/// Insert a `tEXt` ancillary chunk (`keyword` NUL `text`) right after the
/// mandatory IHDR chunk (byte offset 33), with a correct CRC-32 over the chunk
/// type and data. The caller must have validated the signature and IHDR presence.
/// The pixel data (IDAT) and every other chunk are copied byte-for-byte.
fn write_png_text_chunk(png: &[u8], keyword: &[u8], text: &[u8]) -> Vec<u8> {
    // tEXt chunk data: keyword, a NUL separator, then the text.
    let mut chunk_data: Vec<u8> = Vec::with_capacity(keyword.len() + 1 + text.len());
    chunk_data.extend_from_slice(keyword);
    chunk_data.push(0x00);
    chunk_data.extend_from_slice(text);

    // CRC covers the chunk type followed by the chunk data.
    let mut crc_input: Vec<u8> = b"tEXt".to_vec();
    crc_input.extend_from_slice(&chunk_data);
    let crc = crc32(&crc_input);

    let mut chunk: Vec<u8> = Vec::with_capacity(12 + chunk_data.len());
    chunk.extend_from_slice(&(chunk_data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"tEXt");
    chunk.extend_from_slice(&chunk_data);
    chunk.extend_from_slice(&crc.to_be_bytes());

    // Inject right after the IHDR chunk (8 signature + 25 IHDR = offset 33).
    let mut out = Vec::with_capacity(png.len() + chunk.len());
    out.extend_from_slice(&png[..33]);
    out.extend_from_slice(&chunk);
    out.extend_from_slice(&png[33..]);
    out
}

/// Scan a PNG byte stream for a `tEXt` chunk whose keyword equals `keyword` and
/// return its text as a UTF-8 string, or `None` when absent.
fn read_png_text_chunk(png: &[u8], keyword: &[u8]) -> Option<String> {
    if png.len() < 33 || &png[..8] != PNG_SIG {
        return None;
    }
    let mut pos = 8usize; // skip the signature
    loop {
        if pos + 8 > png.len() {
            break;
        }
        let length = u32::from_be_bytes(png[pos..pos + 4].try_into().ok()?) as usize;
        let chunk_type = &png[pos + 4..pos + 8];
        let data_start = pos + 8;
        let data_end = data_start.checked_add(length)?;
        if data_end + 4 > png.len() {
            break;
        }
        if chunk_type == b"tEXt" {
            let data = &png[data_start..data_end];
            if let Some(sep) = data.iter().position(|&b| b == 0) {
                if &data[..sep] == keyword {
                    return String::from_utf8(data[sep + 1..].to_vec()).ok();
                }
            }
        }
        if chunk_type == b"IEND" {
            break;
        }
        pos = data_end + 4; // advance past the CRC
    }
    None
}

// ── CRC-32 (PNG chunk integrity, channel-owned) ───────────────────────────────

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[idx];
    }
    !crc
}

// ── SVG: <metadata> CDATA (reusing the seed's reader) ─────────────────────────

fn embed_svg(svg_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, MetadataError> {
    let svg = std::str::from_utf8(svg_bytes).map_err(|_| MetadataError::Carrier {
        format: "svg",
        detail: "SVG is not valid UTF-8".to_string(),
    })?;

    // The seed's `embed_latex_in_svg` inserts after the FIRST '>' in the whole
    // string, which places the metadata BEFORE the root element when an <?xml?>
    // or <!DOCTYPE> prologue is present, producing invalid SVG. This channel
    // hardens the insertion: locate the <svg root open tag, then its closing '>',
    // and insert the metadata as the root's first child.
    let svg_pos = find_svg_open(svg).ok_or_else(|| MetadataError::Carrier {
        format: "svg",
        detail: "no <svg> root element found".to_string(),
    })?;
    let tag_end = svg[svg_pos..]
        .find('>')
        .map(|p| svg_pos + p + 1)
        .ok_or_else(|| MetadataError::Carrier {
            format: "svg",
            detail: "the <svg> opening tag is not terminated".to_string(),
        })?;

    // A self-closing root (<svg .../>) has no element body to host a child
    // <metadata>; refuse rather than emit malformed markup.
    if svg[..tag_end].trim_end().ends_with("/>") {
        return Err(MetadataError::Carrier {
            format: "svg",
            detail: "the <svg> root is self-closing and has no body to host metadata".to_string(),
        });
    }

    // base64 contains no ']]>' so no CDATA escaping is needed. The element uses
    // this channel's own SteganoHero-owned, technique-neutral markers, matched by
    // [`extract_svg_metadata`] on recovery.
    let element = format!(
        "<metadata xmlns:{p}=\"{ns}\"><{p}:{tag}><![CDATA[{data}]]></{p}:{tag}></metadata>",
        p = SVG_NS_PREFIX,
        ns = SVG_NS_URI,
        tag = SVG_PAYLOAD_TAG,
        data = base64_encode(payload),
    );

    let mut out = String::with_capacity(svg.len() + element.len());
    out.push_str(&svg[..tag_end]);
    out.push_str(&element);
    out.push_str(&svg[tag_end..]);
    Ok(out.into_bytes())
}

fn recover_svg(svg_bytes: &[u8]) -> Result<Option<Vec<u8>>, MetadataError> {
    let svg = std::str::from_utf8(svg_bytes).map_err(|_| MetadataError::Unreadable {
        format: "svg",
        detail: "SVG is not valid UTF-8".to_string(),
    })?;
    match extract_svg_metadata(svg) {
        None => Ok(None),
        Some(encoded) => base64_decode(&encoded)
            .map(Some)
            .map_err(|detail| MetadataError::Unreadable { format: "svg", detail }),
    }
}

/// Extract the base64 text this channel wrote into the SVG `<metadata>` element,
/// or `None` when absent. The payload is base64 (no `]]>`), so the CDATA content
/// is returned verbatim with no unescaping.
fn extract_svg_metadata(svg: &str) -> Option<String> {
    let open = format!("<{p}:{tag}><![CDATA[", p = SVG_NS_PREFIX, tag = SVG_PAYLOAD_TAG);
    let close = format!("]]></{p}:{tag}>", p = SVG_NS_PREFIX, tag = SVG_PAYLOAD_TAG);
    let start = svg.find(&open)? + open.len();
    let end = svg[start..].find(&close)? + start;
    Some(svg[start..end].to_string())
}

/// Find the byte offset of the `<svg` root opening tag (case-insensitive),
/// skipping look-alikes such as `<svgfoo`. Returns `None` if there is no `<svg`
/// element.
fn find_svg_open(svg: &str) -> Option<usize> {
    let bytes = svg.as_bytes();
    let lower = svg.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find("<svg") {
        let idx = from + rel;
        let after = idx + 4;
        match bytes.get(after) {
            // A real <svg tag is followed by whitespace, '>' or '/'.
            Some(&b) if b == b'>' || b == b'/' || b.is_ascii_whitespace() => return Some(idx),
            None => return Some(idx),
            _ => from = after,
        }
    }
    None
}

// ── base64 (hand-ported, pure Rust, no dependency) ────────────────────────────

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding. Output is ASCII, valid in XML text and PNG
/// `tEXt`, and never contains `]]>`.
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 (padding required, ASCII whitespace ignored). Returns a
/// named error on any malformed input, so a corrupt channel is reported rather
/// than silently truncated.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut reverse = [255u8; 256];
    let mut i = 0usize;
    while i < 64 {
        reverse[B64_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }

    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if cleaned.len() % 4 != 0 {
        return Err(format!(
            "base64 length {} is not a multiple of 4",
            cleaned.len()
        ));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks(4) {
        let (c0, c1, c2, c3) = (chunk[0], chunk[1], chunk[2], chunk[3]);
        let v0 = reverse[c0 as usize];
        let v1 = reverse[c1 as usize];
        if v0 == 255 || v1 == 255 {
            return Err("invalid base64 character".to_string());
        }
        let mut n = (v0 as u32) << 18 | (v1 as u32) << 12;
        out.push((n >> 16) as u8);

        if c2 == b'=' {
            // A pad in the third position requires a pad in the fourth.
            if c3 != b'=' {
                return Err("invalid base64 padding".to_string());
            }
            continue;
        }
        let v2 = reverse[c2 as usize];
        if v2 == 255 {
            return Err("invalid base64 character".to_string());
        }
        n |= (v2 as u32) << 6;
        out.push((n >> 8) as u8);

        if c3 == b'=' {
            continue;
        }
        let v3 = reverse[c3 as usize];
        if v3 == 255 {
            return Err("invalid base64 character".to_string());
        }
        n |= v3 as u32;
        out.push(n as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_every_length_class() {
        // Lengths that exercise 0, 1 and 2 trailing bytes (padding cases).
        for len in [0usize, 1, 2, 3, 4, 5, 6, 255, 256] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = base64_encode(&payload);
            assert!(
                encoded.bytes().all(|b| b.is_ascii() && b != b']' && b != b'>'),
                "base64 output must be ASCII and free of CDATA-terminating bytes"
            );
            let decoded = base64_decode(&encoded).expect("valid base64 must decode");
            assert_eq!(decoded, payload, "round trip failed at len {len}");
        }
    }

    #[test]
    fn base64_round_trips_all_byte_values() {
        let payload: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let decoded = base64_decode(&base64_encode(&payload)).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn base64_rejects_malformed_input() {
        assert!(base64_decode("AAA").is_err(), "length not a multiple of 4");
        assert!(base64_decode("AA=A").is_err(), "pad followed by non-pad");
        assert!(base64_decode("**==").is_err(), "invalid alphabet character");
    }

    #[test]
    fn find_svg_open_skips_lookalikes() {
        assert_eq!(find_svg_open("<svg>"), Some(0));
        assert_eq!(find_svg_open("<?xml?><svg "), Some(7));
        assert_eq!(find_svg_open("<svgfoo><svg>"), Some(8));
        assert_eq!(find_svg_open("<rect/>"), None);
    }
}
