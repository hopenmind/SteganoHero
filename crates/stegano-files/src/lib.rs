//! # stegano-files
//!
//! The file layer for SteganoHero: load a real document and extract its text so
//! the text tools (inspect, clean, conceal, provenance mark, C2PA read) can
//! operate on documents, not just strings.
//!
//! It reads and extracts text from a wide document set: the ZIP-container Office
//! formats (DOCX, ODT, PPTX, EPUB), the markup and lightweight-markup formats
//! (HTML, Markdown, RTF, LaTeX, Org, reStructuredText, MediaWiki, AsciiDoc,
//! Typst source, FictionBook), the data and record formats (Jupyter notebooks,
//! BibTeX, CSV/TSV, email), plain source code, and plain/legacy-encoded text.
//! It is dependency-light by design: only `zip` (ZIP containers), `quick-xml`
//! (document XML) and `serde_json` (Jupyter JSON) are added on top of
//! `thiserror`. No headless browser, no Typst engine, no system tool: every
//! importer is pure string, ZIP or JSON processing.
//!
//! PDF *import* remains the one deliberate gap. Reading text out of a PDF is an
//! unsolved problem here (and in the upstream converter tree these importers come from):
//! there is no pure-Rust seed for it, so it is future work rather than a design
//! choice. PDF *output* now exists as a conversion target (Phase D1): a document
//! is lowered to the Markdown waypoint, rendered to self-contained HTML, and
//! printed to PDF by driving a browser the user already has installed, detected at
//! run time and never bundled (see [`convert_file`] and the `pdf` module). That
//! output path is unrelated to PDF import: a PDF *source* is still refused by name
//! (invariant 2), and a host with no suitable browser is refused by name too
//! rather than producing an empty file. The pure-Rust Typst fallback for such
//! hosts is a separate later slice.
//!
//! ## Provenance
//!
//! The extraction internals are copied, not depended upon, from the owner's
//! the upstream converter project (`crates/core/src/text_encoding.rs`, `import_xml.rs`, and
//! the pure-Rust extractors in `import.rs`). the upstream converter's `mdall-core` is
//! monolithic and drags in Typst and a headless Chromium, so a crate dependency
//! would blow the self-contained, small-binary posture. Each copied module
//! records its source path. Re-sync from the upstream converter if that tree's copies move.
//!
//! ## Write-back
//!
//! Extraction retains enough structure to write back (see [`Container`]). The
//! [`transform`] module ties extraction to the frozen core's operations: inspect
//! (read-only) on every format, clean (removal) with a lossless write-back for
//! the text-native and Office-container formats, and conceal (embedding a secret
//! through the core's compose path) for the text-native formats. Any (format,
//! operation) combination whose write-back cannot be proven is refused by name,
//! never approximated (invariant 2).

pub mod convert;
pub mod text_encoding;
pub mod transform;

mod container;
mod docx_common;
mod export;
mod html;
mod image_metadata;
mod import;
mod md_common;
mod metadata;
mod native_metadata;
mod office_xml;
mod pdf;
mod pdf_native;
mod pdf_text;
mod provenance_metadata;
mod strip;
mod writeback;

use std::path::Path;

// The transform surface and the core sovereignty types it hands back, re-exported
// so callers depend on `stegano-files` alone for the file-level operations.
pub use transform::{
    clean_file, clean_path, conceal_file, conceal_path, inspect_file, inspect_path, pristine_file,
    pristine_path, strip_file, strip_path, CleanOutcome, ConcealOutcome, PristineOutcome,
    StripOutcome, TransformError,
};
// The format-to-format conversion capability (Phase C): DECLARED LOSSY, SEPARATE
// FROM MARKING. It extracts a source to a Markdown waypoint and regenerates a
// target with a copied pure-Rust exporter; it never places a mark. Every
// unsupported target (the Typst-linked containers, PDF, import-only formats) is
// refused by name. See the `convert` module doc.
pub use convert::{
    convert_file, export_text, is_supported_target, pdf_target_available, supported_targets,
    target_from_extension, unsupported_target_reason, ConvertError,
};
// The standalone, engine-level metadata channel: the additive, zero-loss
// provenance route (write a payload into a file's metadata surface, leaving the
// document content byte-for-byte unchanged). DOCX, PNG and SVG only; every other
// format is refused by name. Not yet wired to the provenance binding trait.
pub use metadata::{embed_metadata, recover_metadata, MetadataError, DOCX_METADATA_ENTRY};
pub use strip::{strip_metadata, StripError};
// The native-metadata READ side of the pillar: read the standard metadata a
// document format exposes itself (Office docProps for DOCX/ODT in this slice).
// Distinct from the additive channel above; every unsupported format is refused
// by name.
pub use native_metadata::{read_native_metadata, CustomProperty, NativeMetadata};
// The image-metadata READ side of the pillar: read the EXIF and XMP an image
// carries (JPEG, TIFF, PNG, WebP). Distinct from both the additive channel and
// the Office docProps reader above; it reports exactly what an image declares
// (GPS as presence only, no advice), and every non-image format is refused by
// name. See the module doc for the honest-failure contract.
pub use image_metadata::{read_image_metadata, ExifTag, ImageMetadata};
// The format-metadata provenance route: sign a provenance claim over a document
// and bind it into the document's own metadata channel, then verify it back. It
// composes the core provenance layer with the metadata channel above; it is NOT
// a `provenance::Binding` trait impl (the trait is text-only). DOCX is served;
// PNG, SVG and channel-less formats are refused by name. See the module doc.
pub use provenance_metadata::{
    sign_into_metadata, verify_from_metadata, ProvenanceMetadataError, BINDING_KIND,
};
// The core provenance and signing types this route's API takes and returns,
// re-exported so a caller depends on `stegano-files` alone for the format-metadata
// provenance route.
pub use stegano_core::provenance::{
    AiGenerated, Assertion, HumanAuthorship, Integrity, KeyRequirement, ProvenanceReport,
    PublicKeyRef, RecipientFingerprint, Robustness, RobustnessClass, TrustPolicy, UnmetRequirement,
    VerifiedClaim, KIND_AI_GENERATED, KIND_HUMAN_AUTHORSHIP, KIND_INTEGRITY,
    KIND_RECIPIENT_FINGERPRINT,
};
pub use stegano_core::signing::{MasterKeyPair, MasterPublicKey};
pub use stegano_core::sovereignty::{
    pristine_clean, ClassRemoval, CleanReport, InspectionReport, MarkClass, PristineReport,
};
// The core carrier/cipher traits the conceal surface takes, re-exported so a
// caller depends on `stegano-files` alone for the file-level conceal operation.
pub use stegano_core::traits::{CryptoMethod, StegoMethod};

/// An error from the file layer. Every variant names itself and its context; no
/// path returns empty or unchanged input silently (invariant 2).
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    /// The extension maps to no supported SOURCE format. Carries the offending
    /// extension so the caller can report it. PDF import lands here in this build:
    /// PDF is a convert TARGET only (Phase D1), never a text source.
    #[error("unsupported file format: {0}")]
    Unsupported(String),

    /// The path carries no extension, so its format cannot be inferred.
    #[error("cannot infer format: no file extension on {0}")]
    NoExtension(String),

    /// Reading the file from disk failed.
    #[error("cannot read file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Text extraction ran but could not keep its promise (unreadable container,
    /// missing content part, malformed XML, empty result). Names the format.
    #[error("{format} text extraction failed: {detail}")]
    Extraction {
        format: &'static str,
        detail: String,
    },
}

/// A source document format this layer can read.
///
/// The variants split into three write-back families, recorded by the [`Container`]
/// each produces: text-native formats whose extracted text IS the document
/// (`Markdown`, `PlainText`); ZIP-container Office formats retained for a surgical
/// in-place rewrite (`Docx`, `Odt`); and the wider set whose extraction lowers a
/// foreign source to Markdown (everything else), for which a lossless write-back
/// in the original format is not solved in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// Office Open XML word processing document (`.docx`), a ZIP container.
    Docx,
    /// OpenDocument text (`.odt`), a ZIP container.
    Odt,
    /// Office Open XML presentation (`.pptx`), a ZIP container.
    Pptx,
    /// EPUB e-book (`.epub`), a ZIP container of XHTML chapters.
    Epub,
    /// HTML / XHTML (`.html`, `.htm`, `.xhtml`).
    Html,
    /// Markdown (`.md`, `.markdown`).
    Markdown,
    /// Rich Text Format (`.rtf`).
    Rtf,
    /// LaTeX / TeX source (`.tex`, `.latex`).
    Latex,
    /// Emacs Org-mode (`.org`).
    Org,
    /// reStructuredText (`.rst`).
    Rst,
    /// MediaWiki markup (`.wiki`, `.mediawiki`).
    Wiki,
    /// AsciiDoc (`.adoc`, `.asciidoc`, `.asc`).
    AsciiDoc,
    /// Typst source (`.typ`).
    Typst,
    /// Jupyter notebook (`.ipynb`), a JSON document.
    Ipynb,
    /// BibTeX bibliography (`.bib`).
    Bibtex,
    /// FictionBook e-book (`.fb2`), an XML document.
    Fb2,
    /// Email message (`.eml`).
    Eml,
    /// Comma- or tab-separated values (`.csv`, `.tsv`), delimiter auto-detected.
    Csv,
    /// Plain source code, carrying the fenced-block language identifier resolved
    /// from the file extension (e.g. `Code("rust")` for `.rs`).
    Code(&'static str),
    /// Plain UTF-8 / legacy-encoded text (`.txt`, `.text`).
    PlainText,

    // ── Metadata-carrier asset formats ──────────────────────────────────────
    // These are neither text-native nor lowered documents: they carry no
    // extractable document prose, so [`extract_text`] refuses them by name. They
    // exist here because they DO carry a metadata channel (see [`embed_metadata`]),
    // the additive zero-loss provenance route.
    /// PNG raster image (`.png`): a metadata carrier, not extractable text.
    Png,
    /// SVG vector image (`.svg`): a metadata carrier, not extractable text.
    Svg,
    /// JPEG raster image (`.jpg`, `.jpeg`): an image-metadata (EXIF/XMP) source,
    /// not extractable text.
    Jpeg,
    /// TIFF raster image (`.tif`, `.tiff`): an image-metadata (EXIF/XMP) source,
    /// not extractable text.
    Tiff,
    /// WebP raster image (`.webp`): an image-metadata (EXIF/XMP) source, not
    /// extractable text.
    Webp,

    // ── Convert-target-only formats ─────────────────────────────────────────
    /// Portable Document Format (`.pdf`): a conversion TARGET ONLY (Phase D1),
    /// produced by driving a detected local browser headless (see
    /// [`convert::convert_file`]). PDF is not a text source: [`FileFormat::from_extension`]
    /// does NOT resolve `.pdf` to this variant (PDF import stays unsupported), and
    /// [`extract_text`] refuses it by name, like the image carriers, so it can never
    /// be a mark carrier or a conversion source. As a target it is named through
    /// [`convert::target_from_extension`], not the source-intake resolver.
    Pdf,
}

impl FileFormat {
    /// Stable lower-case identifier, used in messages and by callers.
    pub fn name(self) -> &'static str {
        match self {
            FileFormat::Docx => "docx",
            FileFormat::Odt => "odt",
            FileFormat::Pptx => "pptx",
            FileFormat::Epub => "epub",
            FileFormat::Html => "html",
            FileFormat::Markdown => "markdown",
            FileFormat::Rtf => "rtf",
            FileFormat::Latex => "latex",
            FileFormat::Org => "org",
            FileFormat::Rst => "rst",
            FileFormat::Wiki => "wiki",
            FileFormat::AsciiDoc => "asciidoc",
            FileFormat::Typst => "typst",
            FileFormat::Ipynb => "ipynb",
            FileFormat::Bibtex => "bibtex",
            FileFormat::Fb2 => "fb2",
            FileFormat::Eml => "eml",
            FileFormat::Csv => "csv",
            FileFormat::Code(_) => "code",
            FileFormat::PlainText => "text",
            FileFormat::Png => "png",
            FileFormat::Svg => "svg",
            FileFormat::Jpeg => "jpeg",
            FileFormat::Tiff => "tiff",
            FileFormat::Webp => "webp",
            FileFormat::Pdf => "pdf",
        }
    }

    /// Map a file extension (without the dot, any case) to a format. An unknown
    /// extension raises [`FilesError::Unsupported`] by name; it never guesses.
    pub fn from_extension(ext: &str) -> Result<Self, FilesError> {
        match ext.to_ascii_lowercase().as_str() {
            "docx" => Ok(FileFormat::Docx),
            "odt" => Ok(FileFormat::Odt),
            "pptx" => Ok(FileFormat::Pptx),
            "epub" => Ok(FileFormat::Epub),
            "html" | "htm" | "xhtml" => Ok(FileFormat::Html),
            "md" | "markdown" | "mdown" | "mkd" => Ok(FileFormat::Markdown),
            "rtf" => Ok(FileFormat::Rtf),
            "tex" | "latex" => Ok(FileFormat::Latex),
            "org" => Ok(FileFormat::Org),
            "rst" => Ok(FileFormat::Rst),
            "wiki" | "mediawiki" => Ok(FileFormat::Wiki),
            "adoc" | "asciidoc" | "asc" => Ok(FileFormat::AsciiDoc),
            "typ" => Ok(FileFormat::Typst),
            "ipynb" => Ok(FileFormat::Ipynb),
            "bib" => Ok(FileFormat::Bibtex),
            "fb2" => Ok(FileFormat::Fb2),
            "eml" => Ok(FileFormat::Eml),
            "csv" | "tsv" => Ok(FileFormat::Csv),
            "txt" | "text" => Ok(FileFormat::PlainText),
            // Metadata-carrier asset formats (no text extraction; see extract_text).
            "png" => Ok(FileFormat::Png),
            "svg" => Ok(FileFormat::Svg),
            "jpg" | "jpeg" => Ok(FileFormat::Jpeg),
            "tif" | "tiff" => Ok(FileFormat::Tiff),
            "webp" => Ok(FileFormat::Webp),
            // NB: `pdf` is deliberately absent. This is the SOURCE-intake resolver,
            // and PDF import stays unsupported (refused by name here). PDF is a
            // convert TARGET only, named through [`convert::target_from_extension`].
            // Plain source code: the extension resolves the fenced-block language.
            other => match code_language(other) {
                Some(lang) => Ok(FileFormat::Code(lang)),
                None => Err(FilesError::Unsupported(other.to_string())),
            },
        }
    }

    /// Infer the format from a path's extension.
    pub fn from_path(path: &Path) -> Result<Self, FilesError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => Self::from_extension(ext),
            None => Err(FilesError::NoExtension(path.display().to_string())),
        }
    }
}

/// Map a source-code extension to its fenced-block language identifier, or `None`
/// when the extension is not a recognised source-code type. The mapping mirrors
/// the upstream converter importer dispatcher (`crates/core/src/convert.rs`).
fn code_language(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "py" => "python",
        "js" => "javascript",
        "ts" => "typescript",
        "rs" => "rust",
        "c" => "c",
        "cpp" | "cxx" | "cc" => "cpp",
        "java" => "java",
        "go" => "go",
        "rb" => "ruby",
        "php" => "php",
        "sh" | "bash" | "zsh" => "bash",
        "r" => "r",
        _ => return None,
    })
}

/// What extraction retained for a later write-back slice.
///
/// Write-back is not implemented in this slice. These variants record what each
/// format keeps so the next slice can do a faithful, format-appropriate rewrite.
#[derive(Debug, Clone)]
pub enum Container {
    /// Text formats (Markdown, plain text): the extracted `text` IS the source,
    /// so nothing else is retained. Write-back re-encodes the text.
    Source,

    /// HTML: the original decoded markup, retained because extraction lowers it
    /// to Markdown (a lossy transform), so a faithful write-back needs the source.
    Markup { original: String },

    /// ZIP-based Office documents (DOCX, ODT): the whole original archive plus
    /// the primary content part, retained for a later surgical in-place rewrite
    /// of its text runs (the lossless marking route named in the audit).
    OfficeZip {
        /// The original archive bytes, untouched.
        archive: Vec<u8>,
        /// Archive path of the primary content part (e.g. `word/document.xml`).
        entry: String,
        /// Raw XML of that part, as read from the archive.
        xml: String,
    },

    /// Foreign formats whose extraction LOWERS the source to Markdown (EPUB,
    /// PPTX, RTF, LaTeX, Org, RST, MediaWiki, AsciiDoc, Typst, Jupyter, BibTeX,
    /// FictionBook, email, CSV/TSV, source code). The extracted text is a
    /// best-effort rendering, not the source, so a lossless write-back in the
    /// original format is not solved in this build. Inspect (read-only) works on
    /// every such format; clean and conceal are refused by name rather than
    /// approximated (invariant 2). Nothing is retained because no faithful
    /// rewrite is possible yet; when one is added, this variant carries what it
    /// needs.
    Lowered,
}

/// The text extracted from a document, plus its format and retained structure.
#[derive(Debug, Clone)]
pub struct ExtractedText {
    /// Visible text of the document. For the rich formats (DOCX, ODT, HTML) this
    /// is a Markdown rendering that preserves headings, emphasis, lists and
    /// tables; for Markdown and plain text it is the decoded content unchanged.
    pub text: String,
    /// The source format the text came from.
    pub format: FileFormat,
    /// What was retained for a later write-back slice. See [`Container`].
    pub container: Container,
}

/// Robustly decode document bytes to a String for the text-based importers: the
/// same front door the Markdown, HTML and plain-text paths use (BOM / UTF-16 /
/// cp1252 aware, plus one mojibake-repair pass that leaves clean text untouched).
fn decode_text_bytes(bytes: &[u8]) -> String {
    text_encoding::fix_mojibake(&text_encoding::decode_bytes(bytes))
}

/// Wrap an importer result into an [`ExtractedText`] with the [`Container::Lowered`]
/// marker. Maps a named importer error to [`FilesError::Extraction`], and turns an
/// empty (or whitespace-only) success into a named refusal rather than handing back
/// nothing (invariant 2: no silent degradation).
fn lowered_extract(
    format_name: &'static str,
    format: FileFormat,
    result: Result<String, String>,
) -> Result<ExtractedText, FilesError> {
    let text = result.map_err(|detail| FilesError::Extraction {
        format: format_name,
        detail,
    })?;
    if text.trim().is_empty() {
        return Err(FilesError::Extraction {
            format: format_name,
            detail: "the document carried no readable text".to_string(),
        });
    }
    Ok(ExtractedText {
        text,
        format,
        container: Container::Lowered,
    })
}

/// Extract text from in-memory document bytes of a known [`FileFormat`].
///
/// Rich formats return a Markdown rendering of the visible text; text formats
/// return the decoded content. On any failure the error names the format; an
/// unsupported format never reaches here (it is refused at format selection).
pub fn extract_text(bytes: &[u8], format: FileFormat) -> Result<ExtractedText, FilesError> {
    match format {
        FileFormat::Docx => {
            let z = container::extract_docx(bytes)
                .map_err(|detail| FilesError::Extraction { format: "DOCX", detail })?;
            Ok(ExtractedText {
                text: z.text,
                format,
                container: Container::OfficeZip {
                    archive: bytes.to_vec(),
                    entry: z.entry,
                    xml: z.xml,
                },
            })
        }
        FileFormat::Odt => {
            let z = container::extract_odt(bytes)
                .map_err(|detail| FilesError::Extraction { format: "ODT", detail })?;
            Ok(ExtractedText {
                text: z.text,
                format,
                container: Container::OfficeZip {
                    archive: bytes.to_vec(),
                    entry: z.entry,
                    xml: z.xml,
                },
            })
        }
        FileFormat::Html => {
            let original = text_encoding::fix_mojibake(&text_encoding::decode_bytes(bytes));
            let text = html::html_to_md(&original)
                .map_err(|detail| FilesError::Extraction { format: "HTML", detail })?;
            Ok(ExtractedText {
                text,
                format,
                container: Container::Markup { original },
            })
        }

        // ── ZIP-container formats lowered to Markdown ────────────────────────
        FileFormat::Pptx => lowered_extract("PPTX", format, import::pptx_to_md(bytes)),
        FileFormat::Epub => lowered_extract("EPUB", format, import::epub_to_md(bytes)),

        // ── Text/markup/data formats lowered to Markdown ────────────────────
        FileFormat::Rtf => lowered_extract("RTF", format, import::rtf_to_md(&decode_text_bytes(bytes))),
        FileFormat::Latex => {
            lowered_extract("LaTeX", format, import::tex_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Org => {
            lowered_extract("Org", format, import::org_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Rst => lowered_extract(
            "reStructuredText",
            format,
            import::rst_to_md(&decode_text_bytes(bytes)),
        ),
        FileFormat::Wiki => {
            lowered_extract("MediaWiki", format, import::wiki_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::AsciiDoc => {
            lowered_extract("AsciiDoc", format, import::adoc_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Typst => {
            lowered_extract("Typst", format, import::typ_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Ipynb => {
            lowered_extract("Jupyter", format, import::ipynb_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Bibtex => {
            lowered_extract("BibTeX", format, import::bib_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Fb2 => {
            lowered_extract("FictionBook", format, import::fb2_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Eml => {
            lowered_extract("email", format, import::eml_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Csv => {
            lowered_extract("CSV", format, import::csv_to_md(&decode_text_bytes(bytes)))
        }
        FileFormat::Code(lang) => lowered_extract(
            "source code",
            format,
            import::code_to_md(&decode_text_bytes(bytes), lang),
        ),

        FileFormat::Markdown | FileFormat::PlainText => {
            // Robust decode (BOM / UTF-16 / cp1252) plus one mojibake-repair pass,
            // the same front door the upstream converter uses for text files.
            let text = text_encoding::fix_mojibake(&text_encoding::decode_bytes(bytes));
            Ok(ExtractedText {
                text,
                format,
                container: Container::Source,
            })
        }

        // ── Metadata-carrier asset formats: no extractable document text ─────
        // PNG and SVG carry a metadata channel ([`embed_metadata`]), not document
        // prose. Refuse by name rather than return empty (invariant 2).
        FileFormat::Png => Err(FilesError::Extraction {
            format: "PNG",
            detail: "a raster image carries no extractable document text in this build; its \
                     provenance rides the metadata channel, not the text pipeline"
                .to_string(),
        }),
        FileFormat::Svg => Err(FilesError::Extraction {
            format: "SVG",
            detail: "a vector image carries no extractable document text in this build; its \
                     provenance rides the metadata channel, not the text pipeline"
                .to_string(),
        }),

        // JPEG, TIFF and WebP are image-metadata sources: their standard metadata
        // (EXIF/XMP) is read through the image-metadata reader, not the text
        // pipeline. Refuse by name rather than return empty (invariant 2).
        FileFormat::Jpeg => Err(FilesError::Extraction {
            format: "JPEG",
            detail: "a raster image carries no extractable document text; its standard metadata \
                     (EXIF/XMP) is read through the image-metadata reader, not the text pipeline"
                .to_string(),
        }),
        FileFormat::Tiff => Err(FilesError::Extraction {
            format: "TIFF",
            detail: "a raster image carries no extractable document text; its standard metadata \
                     (EXIF/XMP) is read through the image-metadata reader, not the text pipeline"
                .to_string(),
        }),
        FileFormat::Webp => Err(FilesError::Extraction {
            format: "WebP",
            detail: "a raster image carries no extractable document text; its standard metadata \
                     (EXIF/XMP) is read through the image-metadata reader, not the text pipeline"
                .to_string(),
        }),

        // PDF text SOURCE path: read the PDF's text layer through the pure-Rust
        // reader. The extracted text is a best-effort lowering of the PDF (its
        // layout and fonts are not the source), so it is classified `Lowered`:
        // inspect and analyze read it, but a lossless write-back in PDF is refused
        // by name, exactly as the other lowered formats. An encrypted, unparsable
        // or text-less (scanned) PDF is refused by name, never returned empty
        // (invariant 2). PDF is also a conversion OUTPUT via the export path
        // ([`crate::pdf`]); reading and writing PDF are separate concerns.
        FileFormat::Pdf => lowered_extract(
            "PDF",
            format,
            pdf_text::extract_pdf_text(bytes).map_err(|e| e.to_string()),
        ),
    }
}

/// Read a document from disk and extract its text, inferring the format from the
/// path's extension. An unknown or missing extension raises by name.
pub fn extract_text_from_path(path: &Path) -> Result<ExtractedText, FilesError> {
    let format = FileFormat::from_path(path)?;
    let bytes = std::fs::read(path).map_err(|source| FilesError::Io {
        path: path.display().to_string(),
        source,
    })?;
    extract_text(&bytes, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_extensions_map_to_formats() {
        assert_eq!(FileFormat::from_extension("docx").unwrap(), FileFormat::Docx);
        assert_eq!(FileFormat::from_extension("DOCX").unwrap(), FileFormat::Docx);
        assert_eq!(FileFormat::from_extension("odt").unwrap(), FileFormat::Odt);
        assert_eq!(FileFormat::from_extension("htm").unwrap(), FileFormat::Html);
        assert_eq!(FileFormat::from_extension("md").unwrap(), FileFormat::Markdown);
        assert_eq!(FileFormat::from_extension("txt").unwrap(), FileFormat::PlainText);
    }

    #[test]
    fn unsupported_extension_raises_by_name() {
        // PDF import is the named gap in this build: the SOURCE-intake resolver must
        // refuse `.pdf`, naming itself. (PDF is a convert TARGET only, named through
        // convert::target_from_extension, never resolved here.)
        let err = FileFormat::from_extension("pdf").unwrap_err();
        match &err {
            FilesError::Unsupported(ext) => assert_eq!(ext, "pdf"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert!(err.to_string().contains("pdf"));
    }

    #[test]
    fn pdf_import_is_refused_by_name() {
        // PDF is a conversion OUTPUT only: reading a PDF as a text source must refuse
        // by name rather than return empty or a partial parse (invariant 2). The
        // variant is only ever constructed as a target, never inferred from a source.
        let err = extract_text(b"%PDF-1.7\n", FileFormat::Pdf).unwrap_err();
        match &err {
            FilesError::Extraction { format, .. } => assert_eq!(*format, "PDF"),
            other => panic!("expected Extraction naming PDF, got {other:?}"),
        }
        assert!(err.to_string().contains("PDF"));
    }

    #[test]
    fn missing_extension_raises_by_name() {
        let err = FileFormat::from_path(Path::new("no_extension_here")).unwrap_err();
        assert!(matches!(err, FilesError::NoExtension(_)));
    }

    #[test]
    fn plain_text_round_trips_through_decode() {
        let out = extract_text(b"hello world\n", FileFormat::PlainText).unwrap();
        assert_eq!(out.text, "hello world\n");
        assert_eq!(out.format, FileFormat::PlainText);
        assert!(matches!(out.container, Container::Source));
    }

    #[test]
    fn png_and_svg_extensions_map_to_metadata_carrier_formats() {
        assert_eq!(FileFormat::from_extension("png").unwrap(), FileFormat::Png);
        assert_eq!(FileFormat::from_extension("PNG").unwrap(), FileFormat::Png);
        assert_eq!(FileFormat::from_extension("svg").unwrap(), FileFormat::Svg);
        assert_eq!(FileFormat::Png.name(), "png");
        assert_eq!(FileFormat::Svg.name(), "svg");
    }

    #[test]
    fn extracting_text_from_a_metadata_carrier_format_is_refused_by_name() {
        // PNG/SVG carry a metadata channel, not document text: extraction must
        // refuse by name rather than return empty (invariant 2).
        let err = extract_text(b"\x89PNG\r\n\x1a\n", FileFormat::Png).unwrap_err();
        match &err {
            FilesError::Extraction { format, .. } => assert_eq!(*format, "PNG"),
            other => panic!("expected Extraction naming PNG, got {other:?}"),
        }
        let err = extract_text(b"<svg></svg>", FileFormat::Svg).unwrap_err();
        assert!(err.to_string().contains("SVG"));
    }
}
