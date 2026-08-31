//! SEC-STRIP: metadata is removed and the document CONTENT stays byte-identical,
//! per format. Fixtures are built in-memory, mirroring the other tests.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use stegano_files::{strip_metadata, FileFormat, DOCX_METADATA_ENTRY};

// ── ZIP helpers (DOCX / ODT) ──────────────────────────────────────────────────

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

#[test]
fn docx_strip_drops_docprops_and_our_channel_and_keeps_content() {
    let document = b"<w:document><w:body><w:t>Hello provenance world</w:t></w:body></w:document>";
    let docx = build_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", b"<Relationships/>"),
        ("word/document.xml", document),
        ("docProps/core.xml", b"<coreProperties><creator>Jane</creator></coreProperties>"),
        ("docProps/app.xml", b"<Properties><Application>Word</Application></Properties>"),
        (DOCX_METADATA_ENTRY, b"c3RlZ2Fubw=="),
    ]);

    let stripped = strip_metadata(&docx, FileFormat::Docx).expect("a valid DOCX strips");
    let entries = zip_entries(&stripped);

    // The metadata is gone.
    assert!(!entries.keys().any(|k| k.starts_with("docProps/")));
    assert!(!entries.contains_key(DOCX_METADATA_ENTRY));
    // The content is byte-identical, and the structural entries survive.
    assert_eq!(entries.get("word/document.xml").map(Vec::as_slice), Some(document.as_slice()));
    assert!(entries.contains_key("[Content_Types].xml"));
    assert!(entries.contains_key("_rels/.rels"));
}

#[test]
fn odt_strip_drops_meta_xml_and_keeps_content() {
    let content = b"<office:document-content><office:body>text</office:body></office:document-content>";
    let odt = build_zip(&[
        ("mimetype", b"application/vnd.oasis.opendocument.text"),
        ("content.xml", content),
        ("meta.xml", b"<office:document-meta><meta:creator>Jane</meta:creator></office:document-meta>"),
    ]);

    let stripped = strip_metadata(&odt, FileFormat::Odt).expect("a valid ODT strips");
    let entries = zip_entries(&stripped);

    assert!(!entries.contains_key("meta.xml"));
    assert_eq!(entries.get("content.xml").map(Vec::as_slice), Some(content.as_slice()));
    assert!(entries.contains_key("mimetype"));
}

// ── PNG helpers ───────────────────────────────────────────────────────────────

fn png_chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(12 + data.len());
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(ctype);
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(&[0, 0, 0, 0]); // a placeholder CRC; strip copies verbatim
    chunk
}

/// Walk a PNG and return each chunk type in order.
fn png_chunk_types(png: &[u8]) -> Vec<[u8; 4]> {
    let mut types = Vec::new();
    let mut pos = 8usize;
    while pos + 8 <= png.len() {
        let length = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
        let mut ctype = [0u8; 4];
        ctype.copy_from_slice(&png[pos + 4..pos + 8]);
        types.push(ctype);
        let end = pos + 12 + length;
        if end > png.len() {
            break;
        }
        pos = end;
        if &ctype == b"IEND" {
            break;
        }
    }
    types
}

#[test]
fn png_strip_drops_metadata_chunks_and_keeps_pixels() {
    let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]; // 1x1, 8-bit RGB
    let idat_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut png = Vec::new();
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    png.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&png_chunk(b"tEXt", b"steganohero\0payload"));
    png.extend_from_slice(&png_chunk(b"eXIf", b"exifbytes"));
    png.extend_from_slice(&png_chunk(b"tIME", b"\x07\xe8\x01\x01\x00\x00\x00"));
    png.extend_from_slice(&png_chunk(b"IDAT", &idat_data));
    png.extend_from_slice(&png_chunk(b"IEND", &[]));

    let stripped = strip_metadata(&png, FileFormat::Png).expect("a valid PNG strips");
    let types = png_chunk_types(&stripped);

    assert_eq!(types, vec![*b"IHDR", *b"IDAT", *b"IEND"], "only the image chunks remain");
    // The IDAT (pixel) bytes are byte-identical.
    let idat = png_chunk(b"IDAT", &idat_data);
    assert!(
        stripped.windows(idat.len()).any(|w| w == idat.as_slice()),
        "the IDAT chunk is preserved verbatim"
    );
}

// ── JPEG helpers ──────────────────────────────────────────────────────────────

#[test]
fn jpeg_strip_drops_app1_and_keeps_the_scan() {
    let mut app1_payload = Vec::new();
    app1_payload.extend_from_slice(b"Exif\0\0");
    app1_payload.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // a tiny TIFF stand-in
    let app1_len = (app1_payload.len() + 2) as u16;

    // Everything from SOS onward is copied verbatim by the strip.
    let scan_region: &[u8] = &[0xFF, 0xDA, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xFF, 0xD9];

    let mut jpeg = Vec::new();
    jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI
    jpeg.extend_from_slice(&[0xFF, 0xE1]); // APP1
    jpeg.extend_from_slice(&app1_len.to_be_bytes());
    jpeg.extend_from_slice(&app1_payload);
    jpeg.extend_from_slice(scan_region);

    let stripped = strip_metadata(&jpeg, FileFormat::Jpeg).expect("a valid JPEG strips");

    // The EXIF segment is gone.
    assert!(
        !stripped.windows(4).any(|w| w == b"Exif"),
        "the EXIF marker is removed"
    );
    // The image is byte-identical: SOI then the scan region, nothing else.
    let mut expected = vec![0xFF, 0xD8];
    expected.extend_from_slice(scan_region);
    assert_eq!(stripped, expected);
}
