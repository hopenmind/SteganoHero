//! Image metadata READ (the analyse side of the metadata pillar): read the EXIF
//! and XMP an image carries. These tests build minimal, valid image byte streams
//! in memory: a big-endian TIFF whose IFDs carry real EXIF tags (Make, Orientation,
//! DateTimeOriginal, pixel dimensions, and optionally a GPS IFD), the same TIFF
//! wrapped in a JPEG APP1 Exif segment, and a minimal PNG carrying an XMP packet.
//! They prove the common fields are read, GPS is reported as presence only, an
//! image with neither EXIF nor XMP is an empty-but-explicit result (not an error),
//! a non-image byte stream raises BY NAME, and a non-image format is refused BY
//! NAME (invariant 2).

use stegano_files::{read_image_metadata, FileFormat, MetadataError};

// ── EXIF fixture builders (big-endian "MM" TIFF) ──────────────────────────────

/// Append one 12-byte IFD entry: tag, type, count, and the raw 4-byte value field.
/// For values that fit in 4 bytes the field IS the value (left-justified per the
/// TIFF rule); for larger values it is the offset to the data pool.
fn push_entry(buf: &mut Vec<u8>, tag: u16, typ: u16, count: u32, value4: [u8; 4]) {
    buf.extend_from_slice(&tag.to_be_bytes());
    buf.extend_from_slice(&typ.to_be_bytes());
    buf.extend_from_slice(&count.to_be_bytes());
    buf.extend_from_slice(&value4);
}

/// Build a big-endian TIFF whose primary IFD carries Make, Orientation and an
/// Exif sub-IFD (DateTimeOriginal, pixel dimensions). Offsets are computed against
/// this fixed layout and self-checked with an assertion.
///
/// Layout (byte offsets from the TIFF header):
/// - 0   header (8)
/// - 8   IFD0: count(2) + 3*12 + next(4) = 42  -> ends 50
/// - 50  Make string "Canon\0" (6)            -> ends 56
/// - 56  Exif IFD: count(2) + 3*12 + next(4) = 42 -> ends 98
/// - 98  DateTimeOriginal string (20)         -> ends 118
fn build_tiff_exif() -> Vec<u8> {
    let make = b"Canon\0"; // 6 bytes
    let dto = b"2021:01:01 12:00:00\0"; // 20 bytes
    let make_off: u32 = 50;
    let exif_ifd_off: u32 = 56;
    let dto_off: u32 = 98;

    let mut t = Vec::new();
    // Header: big-endian, TIFF magic 42, IFD0 at offset 8.
    t.extend_from_slice(b"MM");
    t.extend_from_slice(&0x002Au16.to_be_bytes());
    t.extend_from_slice(&8u32.to_be_bytes());

    // IFD0: Make (ASCII), Orientation (SHORT=1), ExifIFDPointer (LONG).
    t.extend_from_slice(&3u16.to_be_bytes());
    push_entry(&mut t, 0x010F, 2, make.len() as u32, make_off.to_be_bytes());
    push_entry(&mut t, 0x0112, 3, 1, [0, 1, 0, 0]); // SHORT 1, left-justified
    push_entry(&mut t, 0x8769, 4, 1, exif_ifd_off.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes()); // no IFD1

    // IFD0 data pool.
    t.extend_from_slice(make);

    // Exif IFD: DateTimeOriginal (ASCII), PixelXDimension=800, PixelYDimension=600.
    t.extend_from_slice(&3u16.to_be_bytes());
    push_entry(&mut t, 0x9003, 2, dto.len() as u32, dto_off.to_be_bytes());
    push_entry(&mut t, 0xA002, 4, 1, 800u32.to_be_bytes());
    push_entry(&mut t, 0xA003, 4, 1, 600u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());

    // Exif data pool.
    t.extend_from_slice(dto);

    assert_eq!(t.len(), 118, "fixture layout must match the computed offsets");
    t
}

/// Build a big-endian TIFF whose primary IFD points to a GPS IFD (one GPSVersionID
/// entry), so the reader sees a field in the GPS context.
///
/// Layout: header(8) + IFD0(count1 -> 18) + GPS IFD(count1 -> 18) = 44.
fn build_tiff_gps() -> Vec<u8> {
    let gps_ifd_off: u32 = 26; // 8 + 18

    let mut t = Vec::new();
    t.extend_from_slice(b"MM");
    t.extend_from_slice(&0x002Au16.to_be_bytes());
    t.extend_from_slice(&8u32.to_be_bytes());

    // IFD0: GPSInfoIFDPointer (LONG) -> GPS IFD.
    t.extend_from_slice(&1u16.to_be_bytes());
    push_entry(&mut t, 0x8825, 4, 1, gps_ifd_off.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());

    // GPS IFD: GPSVersionID (BYTE, count 4), inline value 2.3.0.0.
    t.extend_from_slice(&1u16.to_be_bytes());
    push_entry(&mut t, 0x0000, 1, 4, [2, 3, 0, 0]);
    t.extend_from_slice(&0u32.to_be_bytes());

    assert_eq!(t.len(), 44, "GPS fixture layout must match the computed offsets");
    t
}

/// Wrap a TIFF/EXIF block in a minimal JPEG (SOI, APP1 Exif segment, EOI).
fn wrap_jpeg(tiff: &[u8]) -> Vec<u8> {
    let mut app1 = Vec::new();
    app1.extend_from_slice(b"Exif\0\0");
    app1.extend_from_slice(tiff);
    let seg_len = (app1.len() + 2) as u16; // segment length includes its own 2 bytes

    let mut jpg = Vec::new();
    jpg.extend_from_slice(&[0xFF, 0xD8]); // SOI
    jpg.extend_from_slice(&[0xFF, 0xE1]); // APP1
    jpg.extend_from_slice(&seg_len.to_be_bytes());
    jpg.extend_from_slice(&app1);
    jpg.extend_from_slice(&[0xFF, 0xD9]); // EOI
    jpg
}

// ── PNG fixture builders (CRC is not validated by the reader) ──────────────────

/// One PNG chunk: 4-byte big-endian length, 4-byte type, data, 4-byte CRC. The
/// EXIF reader does not validate the CRC, so a placeholder is used.
fn png_chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&(data.len() as u32).to_be_bytes());
    c.extend_from_slice(ctype);
    c.extend_from_slice(data);
    c.extend_from_slice(&[0, 0, 0, 0]);
    c
}

/// A minimal valid PNG (signature, IHDR, IEND) plus any extra chunks in between.
fn build_png(extra_chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]; // 1x1, 8-bit truecolor
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    for chunk in extra_chunks {
        png.extend_from_slice(chunk);
    }
    png.extend_from_slice(&png_chunk(b"IEND", &[]));
    png
}

const XMP_PACKET: &str = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" \
xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
<rdf:Description rdf:about=\"\">\
<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Sunset</rdf:li></rdf:Alt></dc:title>\
<dc:creator><rdf:Seq><rdf:li>Ada Lovelace</rdf:li></rdf:Seq></dc:creator>\
<dc:rights><rdf:Alt><rdf:li xml:lang=\"x-default\">CC BY 4.0</rdf:li></rdf:Alt></dc:rights>\
</rdf:Description>\
</rdf:RDF></x:xmpmeta>";

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn reads_exif_common_fields_from_a_tiff() {
    let meta = read_image_metadata(&build_tiff_exif(), FileFormat::Tiff).unwrap();
    assert_eq!(meta.format, "tiff");
    assert!(meta.has_exif, "the fixture carries EXIF");
    assert!(!meta.has_xmp, "the fixture carries no XMP");
    assert_eq!(meta.camera_make.as_deref(), Some("Canon"));
    assert_eq!(meta.datetime_original.as_deref(), Some("2021:01:01 12:00:00"));
    assert_eq!(
        meta.orientation.as_deref(),
        Some("row 0 at top and column 0 at left")
    );
    assert_eq!(meta.pixel_width.as_deref(), Some("800"));
    assert_eq!(meta.pixel_height.as_deref(), Some("600"));
    assert!(!meta.gps_present, "the fixture carries no GPS IFD");
    // The raw tag list carries every declared tag for completeness.
    assert!(
        meta.exif_tags.iter().any(|t| t.name == "Make" && t.value.contains("Canon")),
        "raw tag list must include Make=Canon: {:?}",
        meta.exif_tags
    );
    assert!(meta.exif_tags.len() >= 4, "expected several raw tags: {:?}", meta.exif_tags);
}

#[test]
fn reads_exif_from_a_jpeg_app1_segment() {
    let meta = read_image_metadata(&wrap_jpeg(&build_tiff_exif()), FileFormat::Jpeg).unwrap();
    assert_eq!(meta.format, "jpeg");
    assert!(meta.has_exif);
    assert_eq!(meta.camera_make.as_deref(), Some("Canon"));
    assert_eq!(meta.datetime_original.as_deref(), Some("2021:01:01 12:00:00"));
}

#[test]
fn reports_gps_presence_as_a_boolean() {
    let meta = read_image_metadata(&build_tiff_gps(), FileFormat::Tiff).unwrap();
    assert!(meta.has_exif);
    assert!(meta.gps_present, "the GPS IFD must be reported as present");
}

#[test]
fn reads_xmp_dublin_core_from_a_png() {
    let png = build_png(&[png_chunk(b"iTXt", XMP_PACKET.as_bytes())]);
    let meta = read_image_metadata(&png, FileFormat::Png).unwrap();
    assert_eq!(meta.format, "png");
    assert!(!meta.has_exif, "this PNG carries no EXIF");
    assert!(meta.has_xmp, "this PNG carries an XMP packet");
    assert_eq!(meta.xmp_title.as_deref(), Some("Sunset"));
    assert_eq!(meta.xmp_creator.as_deref(), Some("Ada Lovelace"));
    assert_eq!(meta.xmp_rights.as_deref(), Some("CC BY 4.0"));
    // The raw packet is reported verbatim regardless of the parse.
    assert!(meta.xmp_xml.as_deref().unwrap().contains("<x:xmpmeta"));
}

#[test]
fn an_image_with_neither_exif_nor_xmp_is_empty_but_explicit() {
    let png = build_png(&[]);
    let meta = read_image_metadata(&png, FileFormat::Png).unwrap();
    assert_eq!(meta.format, "png");
    assert!(!meta.has_exif, "no EXIF present");
    assert!(!meta.has_xmp, "no XMP present");
    assert!(meta.camera_make.is_none());
    assert!(meta.datetime_original.is_none());
    assert!(meta.xmp_xml.is_none());
    assert!(meta.exif_tags.is_empty());
    assert!(!meta.gps_present);
}

#[test]
fn a_non_image_byte_stream_raises_by_name() {
    // Bytes matching no image container signature: the reader cannot parse them,
    // so this raises rather than returning an empty result (invariant 2).
    let garbage = b"this is plainly not an image, just some text bytes \x00\x01\x02\x03";
    let err = read_image_metadata(garbage, FileFormat::Jpeg).unwrap_err();
    match &err {
        MetadataError::NativeUnreadable { format, .. } => assert_eq!(*format, "jpeg"),
        other => panic!("expected NativeUnreadable naming jpeg, got {other:?}"),
    }
    assert!(err.to_string().contains("jpeg"), "the refusal must name jpeg: {err}");
}

#[test]
fn a_non_image_format_is_refused_by_name() {
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
