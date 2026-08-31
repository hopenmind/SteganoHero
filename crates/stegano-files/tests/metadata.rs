//! The standalone metadata channel (Phase B): the additive, zero-loss provenance
//! route. These tests prove, per format, that embedding a payload leaves the
//! document CONTENT byte-for-byte unchanged, that the payload round-trips
//! (including a binary, non-UTF-8 payload), that an absent channel is not an
//! error, and that a format with no metadata channel is refused BY NAME.
//!
//! Every fixture is built in memory, so the suite needs no on-disk corpus.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use stegano_files::{
    embed_metadata, extract_text, recover_metadata, FileFormat, MetadataError, DOCX_METADATA_ENTRY,
};

/// A binary payload spanning every byte value, including NUL, `]]>` bytes and
/// non-UTF-8 sequences, to prove the channel is payload-agnostic.
fn binary_payload() -> Vec<u8> {
    (0u16..=255).map(|b| b as u8).collect()
}

// ── DOCX helpers ──────────────────────────────────────────────────────────────

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

/// A minimal, readable DOCX: three sibling entries, a real `word/document.xml`
/// the text pipeline can extract.
fn minimal_docx() -> Vec<u8> {
    let doc = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n\
  <w:body>\n\
    <w:p><w:r><w:t xml:space=\"preserve\">Hello provenance world</w:t></w:r></w:p>\n\
  </w:body>\n\
</w:document>";
    build_zip(&[
        ("[Content_Types].xml", "<?xml version=\"1.0\"?><Types/>"),
        ("_rels/.rels", "<?xml version=\"1.0\"?><Relationships/>"),
        ("word/document.xml", doc),
    ])
}

/// Decompressed content of every entry, keyed by name.
fn zip_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut map = BTreeMap::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut content = Vec::new();
        f.read_to_end(&mut content).unwrap();
        map.insert(name, content);
    }
    map
}

/// Entry names in archive order (may contain duplicates).
fn zip_entry_names(bytes: &[u8]) -> Vec<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect()
}

// ── PNG helpers ───────────────────────────────────────────────────────────────

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn png_chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&(data.len() as u32).to_be_bytes());
    c.extend_from_slice(ctype);
    c.extend_from_slice(data);
    let mut crc_input = ctype.to_vec();
    crc_input.extend_from_slice(data);
    c.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    c
}

/// A structurally valid PNG carrying a real IDAT chunk. The IDAT bytes are
/// arbitrary (the channel never parses them); the test only checks they survive
/// the embed byte-for-byte.
fn png_with_idat() -> Vec<u8> {
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR: 1x1, 8-bit grayscale.
    png.extend_from_slice(&png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
    png.extend_from_slice(&png_chunk(
        b"IDAT",
        &[0x08, 0xD7, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
    ));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));
    png
}

/// Walk a PNG into (chunk-type, byte-range) pairs (range covers len+type+data+crc).
fn png_chunks(png: &[u8]) -> Vec<(String, std::ops::Range<usize>)> {
    let mut v = Vec::new();
    let mut pos = 8usize;
    while pos + 8 <= png.len() {
        let len = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
        let ctype = String::from_utf8_lossy(&png[pos + 4..pos + 8]).to_string();
        let end = pos + 12 + len;
        if end > png.len() {
            break;
        }
        let is_end = ctype == "IEND";
        v.push((ctype, pos..end));
        if is_end {
            break;
        }
        pos = end;
    }
    v
}

fn chunk_range(png: &[u8], ctype: &str) -> Option<std::ops::Range<usize>> {
    png_chunks(png)
        .into_iter()
        .find(|(t, _)| t == ctype)
        .map(|(_, r)| r)
}

// ── DOCX tests ────────────────────────────────────────────────────────────────

#[test]
fn docx_round_trip_and_every_other_entry_byte_identical() {
    let docx = minimal_docx();
    let payload = b"a signed provenance claim, opaque bytes".to_vec();

    let out = embed_metadata(&docx, FileFormat::Docx, &payload).unwrap();

    // Round trip.
    assert_eq!(
        recover_metadata(&out, FileFormat::Docx).unwrap().as_deref(),
        Some(payload.as_slice())
    );

    // Every original entry is present in the output with byte-identical content.
    let before = zip_entries(&docx);
    let after = zip_entries(&out);
    for (name, content) in &before {
        assert_eq!(
            after.get(name),
            Some(content),
            "entry {name} was not preserved byte-for-byte"
        );
    }

    // Exactly one entry was added, and it is the metadata entry.
    let added: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
    assert_eq!(added.len(), 1, "exactly one entry may be added");
    assert_eq!(added[0], DOCX_METADATA_ENTRY);

    // The document content (its extracted text) is unchanged.
    assert_eq!(
        extract_text(&out, FileFormat::Docx).unwrap().text,
        extract_text(&docx, FileFormat::Docx).unwrap().text
    );
}

#[test]
fn docx_absent_channel_returns_none() {
    let docx = minimal_docx();
    assert_eq!(recover_metadata(&docx, FileFormat::Docx).unwrap(), None);
}

#[test]
fn docx_re_embed_replaces_and_never_duplicates() {
    let docx = minimal_docx();
    let out1 = embed_metadata(&docx, FileFormat::Docx, b"first").unwrap();
    let out2 = embed_metadata(&out1, FileFormat::Docx, b"second").unwrap();

    assert_eq!(
        recover_metadata(&out2, FileFormat::Docx).unwrap().as_deref(),
        Some(&b"second"[..])
    );
    let occurrences = zip_entry_names(&out2)
        .iter()
        .filter(|n| n.as_str() == DOCX_METADATA_ENTRY)
        .count();
    assert_eq!(occurrences, 1, "a re-embed must replace, not duplicate");
}

// ── PNG tests ─────────────────────────────────────────────────────────────────

#[test]
fn png_round_trip_and_pixel_data_untouched_with_valid_crc() {
    let png = png_with_idat();
    let payload = b"provenance for a PNG asset".to_vec();

    let out = embed_metadata(&png, FileFormat::Png, &payload).unwrap();

    // Round trip.
    assert_eq!(
        recover_metadata(&out, FileFormat::Png).unwrap().as_deref(),
        Some(payload.as_slice())
    );

    // Only a tEXt chunk was added, inserted right after IHDR (offset 33).
    let text = chunk_range(&out, "tEXt").expect("a tEXt chunk must have been added");
    assert_eq!(text.start, 33, "the chunk must be inserted right after IHDR");
    assert_eq!(&out[..text.start], &png[..text.start], "signature + IHDR changed");
    assert_eq!(
        &out[text.end..],
        &png[text.start..],
        "everything after the inserted chunk (IDAT, IEND) must be byte-identical"
    );

    // The CRC we wrote is valid (covers chunk type + data).
    let stored = u32::from_be_bytes(out[text.end - 4..text.end].try_into().unwrap());
    let computed = crc32(&out[text.start + 4..text.end - 4]);
    assert_eq!(stored, computed, "the tEXt chunk CRC-32 must be correct");

    // The pixel data (IDAT) is unchanged, explicitly.
    let idat_before = chunk_range(&png, "IDAT").unwrap();
    let idat_after = chunk_range(&out, "IDAT").unwrap();
    assert_eq!(&out[idat_after], &png[idat_before], "IDAT (pixel data) changed");
}

#[test]
fn png_absent_channel_returns_none() {
    let png = png_with_idat();
    assert_eq!(recover_metadata(&png, FileFormat::Png).unwrap(), None);
}

#[test]
fn png_invalid_carrier_is_refused_by_name_not_silently_returned() {
    // The seed's primitive would return the input unchanged here; the channel
    // must refuse by name instead (invariant 2, no silent degradation).
    let err = embed_metadata(b"this is not a PNG", FileFormat::Png, b"x").unwrap_err();
    match err {
        MetadataError::Carrier { format, .. } => assert_eq!(format, "png"),
        other => panic!("expected Carrier naming png, got {other:?}"),
    }
}

// ── SVG tests ─────────────────────────────────────────────────────────────────

#[test]
fn svg_round_trip_and_markup_untouched_with_xml_prologue() {
    // An SVG with an <?xml?> prologue: the seed's first-'>' insertion would place
    // the metadata before the root; the channel must place it as the root's first
    // child instead.
    let svg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"10\" height=\"10\"><rect width=\"10\" height=\"10\" fill=\"black\"/></svg>";
    let payload = b"provenance for an SVG asset".to_vec();

    let out = embed_metadata(svg.as_bytes(), FileFormat::Svg, &payload).unwrap();
    let out_str = String::from_utf8(out).unwrap();

    // Round trip.
    assert_eq!(
        recover_metadata(out_str.as_bytes(), FileFormat::Svg)
            .unwrap()
            .as_deref(),
        Some(payload.as_slice())
    );

    // Only the <metadata> block was added: strip it, expect the original markup.
    let meta_start = out_str.find("<metadata").unwrap();
    let meta_end = out_str.find("</metadata>").unwrap() + "</metadata>".len();
    let stripped = format!("{}{}", &out_str[..meta_start], &out_str[meta_end..]);
    assert_eq!(stripped, svg, "only the <metadata> block may be added");

    // The metadata is a proper child of the root: after the prologue and the
    // <svg> open, before the drawing content and the </svg> close.
    let p_xml = out_str.find("<?xml").unwrap();
    let p_svg = out_str.find("<svg").unwrap();
    let p_meta = out_str.find("<metadata").unwrap();
    let p_rect = out_str.find("<rect").unwrap();
    let p_close = out_str.find("</svg>").unwrap();
    assert!(
        p_xml < p_svg && p_svg < p_meta && p_meta < p_rect && p_rect < p_close,
        "metadata is not placed as the root's first child"
    );
}

#[test]
fn svg_round_trip_without_prologue() {
    let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><circle r=\"5\"/></svg>";
    let payload = b"claim".to_vec();
    let out = embed_metadata(svg.as_bytes(), FileFormat::Svg, &payload).unwrap();
    assert_eq!(
        recover_metadata(&out, FileFormat::Svg).unwrap().as_deref(),
        Some(payload.as_slice())
    );
}

#[test]
fn svg_absent_channel_returns_none() {
    let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><circle r=\"5\"/></svg>";
    assert_eq!(
        recover_metadata(svg.as_bytes(), FileFormat::Svg).unwrap(),
        None
    );
}

// ── Payload-agnostic: a binary payload round-trips exactly, per format ─────────

#[test]
fn binary_payload_round_trips_exactly_in_every_supported_format() {
    let payload = binary_payload();

    let docx = embed_metadata(&minimal_docx(), FileFormat::Docx, &payload).unwrap();
    assert_eq!(
        recover_metadata(&docx, FileFormat::Docx).unwrap().as_deref(),
        Some(payload.as_slice()),
        "DOCX binary payload did not round-trip exactly"
    );

    let png = embed_metadata(&png_with_idat(), FileFormat::Png, &payload).unwrap();
    assert_eq!(
        recover_metadata(&png, FileFormat::Png).unwrap().as_deref(),
        Some(payload.as_slice()),
        "PNG binary payload did not round-trip exactly"
    );

    let svg_src = "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>";
    let svg = embed_metadata(svg_src.as_bytes(), FileFormat::Svg, &payload).unwrap();
    assert_eq!(
        recover_metadata(&svg, FileFormat::Svg).unwrap().as_deref(),
        Some(payload.as_slice()),
        "SVG binary payload did not round-trip exactly"
    );
}

// ── Carrier markers are SteganoHero-owned and de-techniqued (invariant 8) ─────

/// True when `haystack` contains `needle` as a contiguous byte subsequence.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn emitted_png_carries_the_steganohero_marker_and_no_inherited_names() {
    // A fixed payload whose base64 ("Y2xhaW0=") contains neither inherited marker
    // string, so the assertions are deterministic against the whole emitted file.
    let out = embed_metadata(&png_with_idat(), FileFormat::Png, b"claim").unwrap();

    assert!(
        contains_bytes(&out, b"steganohero"),
        "the PNG tEXt keyword must be the SteganoHero marker"
    );
    assert!(
        !contains_bytes(&out, b"UPSTREAM-CONVERTER"),
        "an emitted PNG must not leak the upstream converter project name"
    );
    assert!(
        !contains_bytes(&out, b"latex"),
        "an emitted PNG must not carry the inherited technique word"
    );

    // The rebranded marker still round-trips.
    assert_eq!(
        recover_metadata(&out, FileFormat::Png).unwrap().as_deref(),
        Some(&b"claim"[..])
    );
}

#[test]
fn emitted_svg_carries_the_steganohero_namespace_and_no_inherited_names() {
    let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>";
    let out = embed_metadata(svg.as_bytes(), FileFormat::Svg, b"claim").unwrap();
    let out = String::from_utf8(out).unwrap();

    assert!(
        out.contains("https://hopenmind.com/steganohero/ns#"),
        "the SVG metadata namespace must be the SteganoHero one: {out}"
    );
    assert!(
        !out.to_lowercase().contains("upstream-converter"),
        "an emitted SVG must not leak the upstream converter project name: {out}"
    );
    assert!(
        !out.contains("latex"),
        "an emitted SVG must not carry the inherited technique word: {out}"
    );

    assert_eq!(
        recover_metadata(out.as_bytes(), FileFormat::Svg)
            .unwrap()
            .as_deref(),
        Some(&b"claim"[..])
    );
}

// ── Refusal by name for formats with no metadata channel ──────────────────────

#[test]
fn formats_without_a_metadata_channel_are_refused_by_name() {
    // Plain text, the lowered formats, and the other containers all lack a
    // metadata channel here and must be refused by name (invariant 2), on both
    // embed and recover.
    let cases = [
        (FileFormat::PlainText, "text"),
        (FileFormat::Markdown, "markdown"),
        (FileFormat::Odt, "odt"),
        (FileFormat::Pptx, "pptx"),
        (FileFormat::Epub, "epub"),
        (FileFormat::Html, "html"),
        (FileFormat::Rtf, "rtf"),
        (FileFormat::Csv, "csv"),
        (FileFormat::Code("rust"), "code"),
    ];
    for (format, name) in cases {
        let err = embed_metadata(b"content", format, b"payload").unwrap_err();
        match &err {
            MetadataError::UnsupportedFormat { format: f } => assert_eq!(*f, name),
            other => panic!("expected UnsupportedFormat for {name}, got {other:?}"),
        }
        assert!(
            err.to_string().contains(name),
            "the refusal must name the format: {err}"
        );

        let err = recover_metadata(b"content", format).unwrap_err();
        assert!(
            matches!(err, MetadataError::UnsupportedFormat { .. }),
            "recover must also refuse {name} by name"
        );
    }
}
