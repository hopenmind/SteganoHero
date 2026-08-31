//! # Image metadata READ: the EXIF and XMP an image carries
//!
//! This is the image side of the metadata pillar's READ surface, and it is
//! DISTINCT from every other metadata route in this crate: it is not the additive
//! channel in [`crate::metadata`] (that writes SteganoHero's OWN payload), and it
//! is not the Office docProps reader in [`crate::native_metadata`] (that reads a
//! document's OWN properties). This module reads what a raster/photo image already
//! declares about itself, so a user can analyse an image before doing anything to
//! it.
//!
//! It reads two standards, pure Rust, no external process, no network:
//!
//! - **EXIF**: the standard camera/photo attributes, read across JPEG, TIFF, PNG
//!   and WebP containers by the `exif` crate (`kamadak-exif`). The common fields
//!   are surfaced by name (camera make and model, original capture time, software,
//!   orientation, pixel dimensions), GPS is reported as a PRESENCE boolean only,
//!   and every declared tag is also kept in a raw name/value list for completeness.
//! - **XMP**: the Adobe/W3C RDF-in-XML metadata packet, embedded verbatim in the
//!   container bytes. The packet is located by a byte scan (it is the same UTF-8
//!   XML text in every container), reported raw, and a few Dublin Core fields
//!   (`dc:title`, `dc:creator`, `dc:rights`) are parsed with the `quick-xml`
//!   already in the crate.
//!
//! ## Analysis, capability-first
//!
//! This reports exactly what the image carries and editorialises nothing. GPS is
//! reported only as a presence flag (the coordinates themselves stay in the raw
//! tag list); there is no advice, no interpretation, no judgement in the result.
//!
//! ## Honest failures (invariant 2)
//!
//! - A format with no image-metadata reader here is refused BY NAME
//!   ([`MetadataError::NoImageMetadata`]), never a silent empty result. Reading
//!   serves JPEG, TIFF, PNG and WebP.
//! - An image that carries NEITHER EXIF nor XMP is NOT an error: it yields an
//!   empty-but-explicit [`ImageMetadata`] (`has_exif` and `has_xmp` both `false`,
//!   every field `None`, the tag list empty). Absent means "the image declares
//!   nothing here", which is a real, honest answer.
//! - A non-image byte stream for an image format, a truncated container, or a
//!   malformed EXIF block raises [`MetadataError::NativeUnreadable`] naming the
//!   format. It is never returned as a partial or fabricated read. A container
//!   that is well-formed but simply carries no EXIF is the absent case above, not
//!   this error.
//! - An XMP packet that is present but whose Dublin Core fields do not parse is
//!   still reported in full through `xmp_xml`: the raw packet is never dropped, so
//!   nothing the image declares is lost even when the parse yields no named field.

use std::io::Cursor;

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};

use crate::metadata::MetadataError;
use crate::FileFormat;

/// A single raw EXIF tag: its standard name and its rendered value, read verbatim
/// from the image for completeness alongside the parsed common fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExifTag {
    /// The tag's standard name (e.g. `"Make"`, `"DateTimeOriginal"`).
    pub name: String,
    /// The tag's value as the image declares it, rendered to text (with unit).
    pub value: String,
}

/// A structured, serde-serializable view of what an image reveals through its
/// standard metadata.
///
/// `has_exif` and `has_xmp` make an empty result explicit: an image with neither
/// is reported as carrying neither, not as an error. Every parsed field is
/// optional; `None` means the image does not declare it. Numeric-looking fields
/// (orientation, dimensions) are kept as the value's own rendered string rather
/// than reinterpreted, so nothing the image states is lost.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageMetadata {
    /// The format these fields were read from (e.g. `"jpeg"`, `"png"`).
    pub format: String,
    /// Whether the image carries an EXIF block at all.
    pub has_exif: bool,
    /// Whether the image carries an XMP packet at all.
    pub has_xmp: bool,

    // ── Common EXIF fields ────────────────────────────────────────────────────
    /// Camera / device manufacturer (`Make`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera_make: Option<String>,
    /// Camera / device model (`Model`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera_model: Option<String>,
    /// Original capture timestamp (`DateTimeOriginal`), as the image's own string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datetime_original: Option<String>,
    /// Producing software or firmware (`Software`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    /// Orientation (`Orientation`), as the reader's rendered description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orientation: Option<String>,
    /// Pixel width (`PixelXDimension`, else the TIFF `ImageWidth`), as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pixel_width: Option<String>,
    /// Pixel height (`PixelYDimension`, else the TIFF `ImageLength`), as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pixel_height: Option<String>,
    /// Whether the EXIF block carries GPS tags. Only PRESENCE is reported: the
    /// coordinate tags themselves remain in [`ImageMetadata::exif_tags`], and
    /// nothing here interprets or advises on them.
    pub gps_present: bool,
    /// Every EXIF tag the image declares, name and rendered value, for
    /// completeness beyond the common fields above (in the reader's field order).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exif_tags: Vec<ExifTag>,

    // ── XMP ───────────────────────────────────────────────────────────────────
    /// The raw XMP packet XML, verbatim, when present. Always reported when a
    /// packet is found, even if no Dublin Core field below parses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmp_xml: Option<String>,
    /// `dc:title` parsed from the XMP packet, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmp_title: Option<String>,
    /// `dc:creator` parsed from the XMP packet, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmp_creator: Option<String>,
    /// `dc:rights` parsed from the XMP packet, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmp_rights: Option<String>,
}

/// Read the EXIF and XMP metadata an image exposes.
///
/// Returns a structured, serde-serializable [`ImageMetadata`]. Supported formats:
/// JPEG, TIFF, PNG and WebP. Every other format is refused BY NAME
/// ([`MetadataError::NoImageMetadata`]); an image with neither EXIF nor XMP yields
/// an empty-but-explicit result; a non-image byte stream, a truncated container,
/// or a malformed EXIF block raises ([`MetadataError::NativeUnreadable`]). See the
/// module docs.
pub fn read_image_metadata(
    bytes: &[u8],
    format: FileFormat,
) -> Result<ImageMetadata, MetadataError> {
    let format_name = match format {
        FileFormat::Jpeg => "jpeg",
        FileFormat::Tiff => "tiff",
        FileFormat::Png => "png",
        FileFormat::Webp => "webp",
        other => return Err(MetadataError::NoImageMetadata { format: other.name() }),
    };

    let mut meta = ImageMetadata {
        format: format_name.to_string(),
        ..Default::default()
    };

    // ── EXIF ──────────────────────────────────────────────────────────────────
    // `NotFound` means the container was parsed successfully and simply carries no
    // EXIF: an honest empty answer, not an error. Any other error (unknown/garbage
    // bytes, a truncated container, a malformed EXIF block) raises BY NAME.
    match exif::Reader::new().read_from_container(&mut Cursor::new(bytes)) {
        Ok(exif) => {
            meta.has_exif = true;
            fill_exif_fields(&exif, &mut meta);
        }
        Err(exif::Error::NotFound(_)) => {
            meta.has_exif = false;
        }
        Err(e) => {
            return Err(MetadataError::NativeUnreadable {
                format: format_name,
                detail: format!("the EXIF block is unreadable: {e}"),
            });
        }
    }

    // ── XMP ───────────────────────────────────────────────────────────────────
    // XMP is a UTF-8 XML packet embedded verbatim in the container, so a byte scan
    // finds it in every one. Report it raw, then best-effort parse a few Dublin
    // Core fields; a packet whose fields do not parse is still reported raw.
    if let Some(xml) = extract_xmp_packet(bytes) {
        meta.has_xmp = true;
        parse_xmp_dublin_core(&xml, &mut meta);
        meta.xmp_xml = Some(xml);
    }

    Ok(meta)
}

// ── EXIF field extraction ─────────────────────────────────────────────────────

/// Fill the common EXIF fields, the GPS presence flag and the raw tag list from a
/// parsed EXIF block.
fn fill_exif_fields(exif: &exif::Exif, meta: &mut ImageMetadata) {
    meta.camera_make = ascii_field(exif, exif::Tag::Make);
    meta.camera_model = ascii_field(exif, exif::Tag::Model);
    meta.datetime_original = ascii_field(exif, exif::Tag::DateTimeOriginal);
    meta.software = ascii_field(exif, exif::Tag::Software);
    meta.orientation = plain_display(exif, exif::Tag::Orientation);
    // Pixel dimensions: the Exif IFD's PixelX/YDimension when present (photo
    // containers), else the TIFF primary IFD's ImageWidth/ImageLength.
    meta.pixel_width = plain_display(exif, exif::Tag::PixelXDimension)
        .or_else(|| plain_display(exif, exif::Tag::ImageWidth));
    meta.pixel_height = plain_display(exif, exif::Tag::PixelYDimension)
        .or_else(|| plain_display(exif, exif::Tag::ImageLength));

    // GPS PRESENCE only: any field in the GPS context marks it present. The
    // coordinates stay in the raw tag list; this flag never leads to advice.
    meta.gps_present = exif
        .fields()
        .any(|f| f.tag.context() == exif::Context::Gps);

    // Every declared tag, name and rendered value (with unit), for completeness.
    meta.exif_tags = exif
        .fields()
        .map(|f| ExifTag {
            name: f.tag.to_string(),
            value: f.display_value().with_unit(exif).to_string(),
        })
        .collect();
}

/// The value of an ASCII EXIF field as a clean string (the raw text, not the
/// quote-wrapped display form), `None` when absent or empty.
fn ascii_field(exif: &exif::Exif, tag: exif::Tag) -> Option<String> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    let text = match &field.value {
        exif::Value::Ascii(parts) => parts
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        // Not an ASCII value: fall back to the reader's rendering.
        _ => field.display_value().to_string(),
    };
    let trimmed = text.trim().trim_matches('\0').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The plain rendered value of an EXIF field (no unit suffix), `None` when absent
/// or empty. Used for the numeric-looking common fields so their value stays
/// clean (e.g. `"800"`, or the orientation description).
fn plain_display(exif: &exif::Exif, tag: exif::Tag) -> Option<String> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    let rendered = field.display_value().to_string();
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ── XMP extraction and Dublin Core parse ──────────────────────────────────────

/// Marker for the XMP packet's conventional outer element and its bare RDF root.
const XMP_META_OPEN: &[u8] = b"<x:xmpmeta";
const XMP_META_CLOSE: &[u8] = b"</x:xmpmeta>";
const XMP_RDF_OPEN: &[u8] = b"<rdf:RDF";
const XMP_RDF_CLOSE: &[u8] = b"</rdf:RDF>";

/// Locate the XMP packet in the raw container bytes and return it as XML text.
/// XMP is embedded verbatim as a UTF-8 XML packet in JPEG (APP1), PNG (a text
/// chunk), TIFF and WebP alike, so a byte-level scan for its outer element finds
/// it in every one. The `x:xmpmeta` wrapper is preferred; a bare `rdf:RDF` packet
/// is the fallback. `None` when no packet is present.
fn extract_xmp_packet(bytes: &[u8]) -> Option<String> {
    slice_between(bytes, XMP_META_OPEN, XMP_META_CLOSE)
        .or_else(|| slice_between(bytes, XMP_RDF_OPEN, XMP_RDF_CLOSE))
}

/// Return the UTF-8 text from the first `open` marker to the end of the first
/// following `close` marker, or `None` if either is absent or the region is not
/// valid UTF-8.
fn slice_between(bytes: &[u8], open: &[u8], close: &[u8]) -> Option<String> {
    let start = find_subsequence(bytes, open)?;
    let rel_end = find_subsequence(&bytes[start..], close)?;
    let end = start + rel_end + close.len();
    std::str::from_utf8(&bytes[start..end]).ok().map(str::to_string)
}

/// Index of the first occurrence of `needle` in `haystack`, or `None`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Which Dublin Core field the current XMP element is capturing into.
enum DcField {
    Title,
    Creator,
    Rights,
}

/// Map an XMP element's QUALIFIED name (prefix included) to the Dublin Core field
/// it fills. The `dc:` prefix is required so a stray unqualified `title` elsewhere
/// in the packet is not captured. Dublin Core in XMP always binds this prefix.
fn dc_field_for(qname: &[u8]) -> Option<DcField> {
    match qname {
        b"dc:title" => Some(DcField::Title),
        b"dc:creator" => Some(DcField::Creator),
        b"dc:rights" => Some(DcField::Rights),
        _ => None,
    }
}

/// Best-effort parse of a few Dublin Core fields (`dc:title`, `dc:creator`,
/// `dc:rights`) from the XMP packet. These are typically wrapped in
/// `rdf:Alt`/`rdf:Seq`/`rdf:Bag` with one or more `rdf:li` items; the text of
/// those items is collected and joined with ", ". A packet that does not parse, or
/// carries none of these fields, leaves them `None`: the raw packet is reported by
/// the caller regardless, so nothing is lost (invariant 2).
fn parse_xmp_dublin_core(xml: &str, meta: &mut ImageMetadata) {
    let mut reader = Reader::from_str(xml);
    let mut active: Option<DcField> = None;
    let mut active_depth: i32 = 0;
    let mut depth: i32 = 0;
    let mut values: Vec<String> = Vec::new();
    let mut accum = String::new();

    loop {
        match reader.read_event() {
            // A malformed packet ends the best-effort parse; the raw XML stands.
            Err(_) | Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if active.is_none() {
                    if let Some(field) = dc_field_for(e.name().as_ref()) {
                        active = Some(field);
                        active_depth = depth;
                        values.clear();
                        accum.clear();
                    }
                } else {
                    // Descending into an inner element (e.g. rdf:Seq, rdf:li):
                    // flush any text run collected so far as its own value.
                    push_trimmed(&mut values, &mut accum);
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                depth -= 1;
                if active.is_some() {
                    push_trimmed(&mut values, &mut accum);
                    if depth == active_depth {
                        let field = active.take().expect("active is Some");
                        let joined = values.join(", ");
                        let joined = joined.trim();
                        if !joined.is_empty() {
                            match field {
                                DcField::Title => meta.xmp_title = Some(joined.to_string()),
                                DcField::Creator => meta.xmp_creator = Some(joined.to_string()),
                                DcField::Rights => meta.xmp_rights = Some(joined.to_string()),
                            }
                        }
                        values.clear();
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if active.is_some() {
                    if let Ok(t) = e.unescape() {
                        accum.push_str(&t);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Push the trimmed accumulated text as a value if it is non-empty, then clear it.
fn push_trimmed(values: &mut Vec<String>, accum: &mut String) {
    let trimmed = accum.trim();
    if !trimmed.is_empty() {
        values.push(trimmed.to_string());
    }
    accum.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_image_format_by_name() {
        for (format, name) in [
            (FileFormat::PlainText, "text"),
            (FileFormat::Markdown, "markdown"),
            (FileFormat::Docx, "docx"),
            (FileFormat::Svg, "svg"),
        ] {
            let err = read_image_metadata(b"anything", format).unwrap_err();
            match &err {
                MetadataError::NoImageMetadata { format: f } => assert_eq!(*f, name),
                other => panic!("expected NoImageMetadata for {name}, got {other:?}"),
            }
            assert!(err.to_string().contains(name), "refusal must name {name}: {err}");
        }
    }

    #[test]
    fn find_subsequence_locates_and_bounds() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello", b"xyz"), None);
        assert_eq!(find_subsequence(b"ab", b"abc"), None);
        assert_eq!(find_subsequence(b"abc", b""), None);
    }

    #[test]
    fn extract_xmp_packet_prefers_xmpmeta_then_rdf() {
        let wrapped = b"junk<x:xmpmeta><rdf:RDF/></x:xmpmeta>junk";
        assert_eq!(
            extract_xmp_packet(wrapped).as_deref(),
            Some("<x:xmpmeta><rdf:RDF/></x:xmpmeta>")
        );
        let bare = b"...<rdf:RDF><a/></rdf:RDF>...";
        assert_eq!(
            extract_xmp_packet(bare).as_deref(),
            Some("<rdf:RDF><a/></rdf:RDF>")
        );
        assert_eq!(extract_xmp_packet(b"no packet here"), None);
    }

    #[test]
    fn parses_simple_and_seq_dublin_core() {
        // Simple text value and a multi-item rdf:Seq, the two common XMP shapes.
        let xml = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
<rdf:RDF xmlns:rdf=\"r\" xmlns:dc=\"d\">\
<rdf:Description>\
<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">A Photo</rdf:li></rdf:Alt></dc:title>\
<dc:creator><rdf:Seq><rdf:li>Ada</rdf:li><rdf:li>Grace</rdf:li></rdf:Seq></dc:creator>\
<dc:rights>All rights reserved</dc:rights>\
</rdf:Description>\
</rdf:RDF></x:xmpmeta>";
        let mut m = ImageMetadata::default();
        parse_xmp_dublin_core(xml, &mut m);
        assert_eq!(m.xmp_title.as_deref(), Some("A Photo"));
        assert_eq!(m.xmp_creator.as_deref(), Some("Ada, Grace"));
        assert_eq!(m.xmp_rights.as_deref(), Some("All rights reserved"));
    }

    #[test]
    fn malformed_xmp_leaves_fields_none_without_panicking() {
        // A truncated packet: the best-effort parse simply yields no field.
        let xml = "<x:xmpmeta><rdf:RDF><dc:creator><rdf:Seq><rdf:li>Half";
        let mut m = ImageMetadata::default();
        parse_xmp_dublin_core(xml, &mut m);
        assert_eq!(m.xmp_creator, None);
    }
}
