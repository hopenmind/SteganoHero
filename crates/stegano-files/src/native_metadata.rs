//! # Native metadata READ: the format's OWN standard metadata
//!
//! This is the READ side of the metadata pillar, and it is DISTINCT from the
//! additive channel in [`crate::metadata`]. That channel writes and recovers
//! SteganoHero's OWN payload; this module reads the metadata a document format
//! natively exposes, so a user can analyse what a file already declares about
//! itself before doing anything to it.
//!
//! This slice covers the Office document-properties parts, pure Rust over the
//! `zip` + `quick-xml` already in the crate, no external process, no network:
//!
//! - **DOCX**: `docProps/core.xml` (Dublin Core / core-properties: title,
//!   subject, creator, keywords, description, lastModifiedBy, created, modified,
//!   category), `docProps/app.xml` (extended-properties: application, company,
//!   word/page/character counts), and `docProps/custom.xml` (custom name/value
//!   pairs) when present.
//! - **ODT**: `meta.xml` (`office:meta`: title, subject, description, creator,
//!   dates, keywords, and `meta:user-defined` custom name/value pairs).
//!
//! ## Honest failures (invariant 2)
//!
//! - A format with no native reader here is refused BY NAME
//!   ([`MetadataError::NoNativeMetadata`]), never a silent empty result. Reading
//!   currently serves DOCX and ODT; images (EXIF/XMP/IPTC) and the other formats
//!   are the next step (see below), not a fabricated empty set.
//! - An ABSENT part (no `docProps/core.xml`, no `meta.xml`) is NOT an error: it
//!   yields an empty-but-explicit [`NativeMetadata`] (the format is named, every
//!   field is `None`, the custom list is empty). Absent means "the document
//!   declares nothing here", which is a real, honest answer.
//! - A part that is PRESENT but unreadable (an unreadable container, a part that
//!   is not valid text, or malformed XML) raises [`MetadataError::NativeUnreadable`]
//!   naming the format. It is never returned as a partial or empty read.
//!
//! ## Next step (not this slice)
//!
//! Image and sidecar metadata standards (EXIF, XMP, IPTC) are deliberately out of
//! this slice: EXIF/IPTC need a binary reader (a small crate) and XMP is RDF/XML
//! that, while expressible with `quick-xml`, is a separate model. They are the
//! declared follow-up, refused by name here until then rather than half-read.

use std::io::{Cursor, Read};

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};

use crate::metadata::MetadataError;
use crate::FileFormat;

/// Hard cap on bytes read from a single ZIP entry (zip-bomb guard), matching the
/// rest of this crate. 128 MiB is far above any legitimate metadata part.
const MAX_ZIP_ENTRY_BYTES: u64 = 128 << 20;

/// A single custom (user-defined) metadata property: a name and its value, read
/// verbatim from the document (`docProps/custom.xml` for DOCX, `meta:user-defined`
/// for ODT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomProperty {
    /// The property name as the document declares it.
    pub name: String,
    /// The property value as the document declares it.
    pub value: String,
}

/// The format-native standard metadata read from a document.
///
/// Every standard field is optional: `None` means the document does not declare
/// it (or declares it empty). Values are read verbatim (trimmed of surrounding
/// whitespace); the count fields are kept as the raw declared strings rather than
/// parsed integers, so nothing the document states is lost or reinterpreted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMetadata {
    /// The format these properties were read from (e.g. `"docx"`, `"odt"`).
    pub format: String,

    // ── Core / Dublin Core properties ────────────────────────────────────────
    /// Document title (`dc:title`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Document subject (`dc:subject`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Author / creator (`dc:creator`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    /// Keywords (`cp:keywords` for DOCX; joined `meta:keyword` values for ODT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keywords: Option<String>,
    /// Description / comments (`dc:description`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The last person who modified the document (`cp:lastModifiedBy`, DOCX).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified_by: Option<String>,
    /// Category (`cp:category`, DOCX).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Creation timestamp (`dcterms:created` for DOCX, `meta:creation-date` for
    /// ODT), as the document's own string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Last-modified timestamp (`dcterms:modified` for DOCX, `dc:date` for ODT),
    /// as the document's own string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,

    // ── Extended (application) properties, DOCX docProps/app.xml ──────────────
    /// Producing application (`Application`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// Company (`Company`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// Word count (`Words`), the raw declared string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word_count: Option<String>,
    /// Page count (`Pages`), the raw declared string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_count: Option<String>,
    /// Character count (`Characters`), the raw declared string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub character_count: Option<String>,

    // ── Custom properties ────────────────────────────────────────────────────
    /// Custom (user-defined) name/value pairs, in document order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom: Vec<CustomProperty>,
}

/// Read the format-NATIVE standard metadata a document exposes.
///
/// Returns a structured, serde-serializable [`NativeMetadata`]. Supported
/// formats: DOCX and ODT (Office docProps / `meta.xml`). Every other format is
/// refused BY NAME ([`MetadataError::NoNativeMetadata`]); an absent part yields an
/// empty-but-explicit result; a present-but-malformed part raises
/// ([`MetadataError::NativeUnreadable`]). See the module docs.
pub fn read_native_metadata(
    bytes: &[u8],
    format: FileFormat,
) -> Result<NativeMetadata, MetadataError> {
    match format {
        FileFormat::Docx => read_docx_native(bytes),
        FileFormat::Odt => read_odt_native(bytes),
        other => Err(MetadataError::NoNativeMetadata { format: other.name() }),
    }
}

// ── DOCX: docProps/{core,app,custom}.xml ──────────────────────────────────────

fn read_docx_native(bytes: &[u8]) -> Result<NativeMetadata, MetadataError> {
    let mut archive = open_archive(bytes, "docx")?;
    let mut meta = NativeMetadata {
        format: "docx".to_string(),
        ..Default::default()
    };

    // Each part is optional: an absent part is not an error (empty-but-explicit),
    // a present part that fails to parse raises by name.
    if let Some(xml) = read_zip_entry(&mut archive, "docProps/core.xml", "docx")? {
        parse_office_meta(&xml, "docx", &mut meta)?;
    }
    if let Some(xml) = read_zip_entry(&mut archive, "docProps/app.xml", "docx")? {
        parse_office_meta(&xml, "docx", &mut meta)?;
    }
    if let Some(xml) = read_zip_entry(&mut archive, "docProps/custom.xml", "docx")? {
        parse_office_meta(&xml, "docx", &mut meta)?;
    }
    Ok(meta)
}

// ── ODT: meta.xml ─────────────────────────────────────────────────────────────

fn read_odt_native(bytes: &[u8]) -> Result<NativeMetadata, MetadataError> {
    let mut archive = open_archive(bytes, "odt")?;
    let mut meta = NativeMetadata {
        format: "odt".to_string(),
        ..Default::default()
    };
    if let Some(xml) = read_zip_entry(&mut archive, "meta.xml", "odt")? {
        parse_office_meta(&xml, "odt", &mut meta)?;
    }
    Ok(meta)
}

// ── Shared ZIP helpers ────────────────────────────────────────────────────────

fn open_archive<'a>(
    bytes: &'a [u8],
    format: &'static str,
) -> Result<zip::ZipArchive<Cursor<&'a [u8]>>, MetadataError> {
    zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| MetadataError::NativeUnreadable {
        format,
        detail: format!("not a valid {} container: {e}", format.to_uppercase()),
    })
}

/// Read a ZIP entry to a String. `Ok(None)` when the entry is absent (not an
/// error), `Err(NativeUnreadable)` when it is present but not readable as text.
fn read_zip_entry(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
    format: &'static str,
) -> Result<Option<String>, MetadataError> {
    match archive.by_name(name) {
        Ok(entry) => {
            let mut s = String::new();
            entry
                .take(MAX_ZIP_ENTRY_BYTES)
                .read_to_string(&mut s)
                .map_err(|e| MetadataError::NativeUnreadable {
                    format,
                    detail: format!("{name} is not valid text: {e}"),
                })?;
            Ok(Some(s))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(MetadataError::NativeUnreadable {
            format,
            detail: format!("cannot open {name}: {e}"),
        }),
    }
}

// ── XML walker ────────────────────────────────────────────────────────────────

/// Which target the current element's text is being captured into.
enum Slot {
    Title,
    Subject,
    Creator,
    Description,
    Keywords,
    KeywordAppend,
    LastModifiedBy,
    Category,
    Created,
    Modified,
    Application,
    Company,
    WordCount,
    PageCount,
    CharacterCount,
    /// A custom property, carrying its declared name.
    Custom(String),
}

/// Map a Start element's LOCAL name (namespace prefix stripped, so a file that
/// binds `dc`/`cp`/`meta` to a different prefix still reads) to the field it
/// fills. Unrecognised elements return `None` and are walked through.
fn slot_for_start(local: &[u8], e: &BytesStart) -> Option<Slot> {
    Some(match local {
        b"title" => Slot::Title,
        b"subject" => Slot::Subject,
        b"creator" => Slot::Creator,
        b"description" => Slot::Description,
        b"keywords" => Slot::Keywords,       // DOCX cp:keywords
        b"keyword" => Slot::KeywordAppend,   // ODT meta:keyword (repeatable)
        b"lastModifiedBy" => Slot::LastModifiedBy,
        b"category" => Slot::Category,
        b"created" => Slot::Created,          // DOCX dcterms:created
        b"creation-date" => Slot::Created,   // ODT meta:creation-date
        b"modified" => Slot::Modified,       // DOCX dcterms:modified
        b"date" => Slot::Modified,           // ODT dc:date (last modified)
        b"Application" => Slot::Application,
        b"Company" => Slot::Company,
        b"Words" => Slot::WordCount,
        b"Pages" => Slot::PageCount,
        b"Characters" => Slot::CharacterCount,
        // Custom properties: DOCX <property name="..."> and ODT
        // <meta:user-defined meta:name="...">. Match the name attribute by its
        // LOCAL name so both the bare and prefixed forms are read.
        b"property" | b"user-defined" => {
            Slot::Custom(attr_by_local(e, b"name").unwrap_or_default())
        }
        _ => return None,
    })
}

/// The value of the attribute whose LOCAL name is `local`, unescaped.
fn attr_by_local(e: &BytesStart, local: &[u8]) -> Option<String> {
    for a in e.attributes().flatten() {
        if a.key.local_name().as_ref() == local {
            return a.unescape_value().ok().map(|v| v.into_owned());
        }
    }
    None
}

/// Commit an accumulated element text to its field. Present-but-empty standard
/// fields are left as `None`; a custom property with an empty name is dropped.
fn commit(meta: &mut NativeMetadata, slot: Slot, raw: &str) {
    if let Slot::Custom(name) = slot {
        let name = name.trim().to_string();
        if !name.is_empty() {
            meta.custom.push(CustomProperty {
                name,
                value: raw.trim().to_string(),
            });
        }
        return;
    }

    let value = raw.trim();
    if value.is_empty() {
        return;
    }
    let v = || value.to_string();
    match slot {
        Slot::Title => meta.title = Some(v()),
        Slot::Subject => meta.subject = Some(v()),
        Slot::Creator => meta.creator = Some(v()),
        Slot::Description => meta.description = Some(v()),
        Slot::Keywords => meta.keywords = Some(v()),
        Slot::KeywordAppend => match &mut meta.keywords {
            Some(existing) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            None => meta.keywords = Some(v()),
        },
        Slot::LastModifiedBy => meta.last_modified_by = Some(v()),
        Slot::Category => meta.category = Some(v()),
        Slot::Created => meta.created = Some(v()),
        Slot::Modified => meta.modified = Some(v()),
        Slot::Application => meta.application = Some(v()),
        Slot::Company => meta.company = Some(v()),
        Slot::WordCount => meta.word_count = Some(v()),
        Slot::PageCount => meta.page_count = Some(v()),
        Slot::CharacterCount => meta.character_count = Some(v()),
        Slot::Custom(_) => unreachable!("custom handled above"),
    }
}

/// Walk one Office metadata XML part and fill `meta`. Depth tracking pins each
/// captured value to the exact element that opened it, so a custom property's
/// nested value element (e.g. `<vt:lpwstr>`) is captured while inner tags do not
/// prematurely close the capture. Any XML error raises by name (invariant 2:
/// malformed docProps is reported, never half-read).
fn parse_office_meta(
    xml: &str,
    format: &'static str,
    meta: &mut NativeMetadata,
) -> Result<(), MetadataError> {
    let mut reader = Reader::from_str(xml);
    // Default (strict) end-name checking, so a mismatched or malformed tag raises
    // rather than being silently tolerated.
    let mut depth: i32 = 0;
    let mut capture: Option<Slot> = None;
    let mut capture_depth: i32 = 0;
    let mut accum = String::new();

    loop {
        let ev = reader
            .read_event()
            .map_err(|e| MetadataError::NativeUnreadable {
                format,
                detail: format!("malformed {} XML: {e}", format.to_uppercase()),
            })?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                let slot = {
                    let name = e.local_name();
                    slot_for_start(name.as_ref(), &e)
                };
                if let Some(s) = slot {
                    capture = Some(s);
                    capture_depth = depth;
                    accum.clear();
                }
                depth += 1;
            }
            Event::End(_) => {
                depth -= 1;
                if capture.is_some() && depth == capture_depth {
                    let slot = capture.take().expect("capture is Some");
                    commit(meta, slot, &accum);
                    accum.clear();
                }
            }
            Event::Text(e) => {
                if capture.is_some() {
                    let t = e.unescape().map_err(|err| MetadataError::NativeUnreadable {
                        format,
                        detail: format!("invalid text content: {err}"),
                    })?;
                    accum.push_str(&t);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_unsupported_format_by_name() {
        for (format, name) in [
            (FileFormat::PlainText, "text"),
            (FileFormat::Markdown, "markdown"),
            (FileFormat::Html, "html"),
            (FileFormat::Png, "png"),
            (FileFormat::Svg, "svg"),
            (FileFormat::Pptx, "pptx"),
        ] {
            let err = read_native_metadata(b"anything", format).unwrap_err();
            match &err {
                MetadataError::NoNativeMetadata { format: f } => assert_eq!(*f, name),
                other => panic!("expected NoNativeMetadata for {name}, got {other:?}"),
            }
            assert!(err.to_string().contains(name), "refusal must name {name}: {err}");
        }
    }

    #[test]
    fn parses_core_fields_and_custom_property_from_xml() {
        // A direct XML-level test of the walker (no ZIP), covering standard
        // fields, a repeated ODT keyword, and a nested-value custom property.
        let core = "<?xml version=\"1.0\"?>\
<cp:coreProperties xmlns:cp=\"x\" xmlns:dc=\"y\" xmlns:dcterms=\"z\">\
<dc:title>My Title</dc:title>\
<dc:creator>Alice</dc:creator>\
<cp:keywords>alpha, beta</cp:keywords>\
<dcterms:created>2020-01-01T00:00:00Z</dcterms:created>\
</cp:coreProperties>";
        let mut m = NativeMetadata::default();
        parse_office_meta(core, "docx", &mut m).unwrap();
        assert_eq!(m.title.as_deref(), Some("My Title"));
        assert_eq!(m.creator.as_deref(), Some("Alice"));
        assert_eq!(m.keywords.as_deref(), Some("alpha, beta"));
        assert_eq!(m.created.as_deref(), Some("2020-01-01T00:00:00Z"));

        let custom = "<Properties xmlns:vt=\"v\">\
<property name=\"Reviewer\"><vt:lpwstr>Bob</vt:lpwstr></property>\
</Properties>";
        parse_office_meta(custom, "docx", &mut m).unwrap();
        assert_eq!(m.custom.len(), 1);
        assert_eq!(m.custom[0].name, "Reviewer");
        assert_eq!(m.custom[0].value, "Bob");
    }

    #[test]
    fn malformed_xml_raises_by_name() {
        let bad = "<cp:coreProperties><dc:title>oops</dc:mismatch></cp:coreProperties>";
        let mut m = NativeMetadata::default();
        let err = parse_office_meta(bad, "docx", &mut m).unwrap_err();
        match &err {
            MetadataError::NativeUnreadable { format, .. } => assert_eq!(*format, "docx"),
            other => panic!("expected NativeUnreadable naming docx, got {other:?}"),
        }
    }
}
