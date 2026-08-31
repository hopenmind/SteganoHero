//! Convert: format-to-format document conversion (Phase C).
//!
//! CONVERSION IS SEPARATE FROM MARKING. This capability is DECLARED LOSSY and
//! best-effort. It extracts the source document to a Markdown waypoint (reusing
//! [`crate::extract_text`]) and regenerates the target from that Markdown with a
//! copied the upstream converter exporter (see [`crate::export`]). Because everything flows
//! through a single Markdown string, target-specific formatting the Markdown
//! cannot express is lost. This is stated plainly here and in the exporter module.
//!
//! It MUST NOT be used to place a mark. Marking is the surgical in-place rewrite /
//! additive-metadata path ([`crate::transform`], [`crate::metadata`]): it never
//! converts, and it keeps the document byte-faithful except for the mark. This
//! module is a distinct code path; it never calls `conceal_file` or the metadata
//! channel, and it carries no placement, carrier, or cipher logic.
//!
//! Honest failure (invariant 2): a source whose text cannot be extracted, and a
//! target for which no pure-Rust exporter is shipped, are both refused BY NAME.
//! Conversion never silently produces a corrupt or empty file. A `source == target`
//! request is a valid pass: it still round-trips through Markdown, so for the
//! lowering formats it normalises rather than reproducing the input byte-for-byte;
//! for the Markdown target it is the waypoint re-emitted unchanged.
//!
//! ## Working targets vs. deferred targets
//!
//! [`supported_targets`] returns the pure-Rust waypoint writers that WORK in this
//! build with no external help: Markdown, HTML, plain text, LaTeX/TeX, RTF, Org,
//! reStructuredText, AsciiDoc, Jupyter (ipynb) and Typst source. The rest are
//! refused by name with the exact reason ([`unsupported_target_reason`]): the
//! binary containers (DOCX, ODT, EPUB) because their the upstream converter exporters link the
//! Typst equation-image renderer and the `image` crate; and the import-only or
//! non-document formats because the reused engine ships no exporter for them.
//!
//! ## PDF: a distinct, browser-backed target (Phase D1)
//!
//! PDF ([`FileFormat::Pdf`]) is a conversion target too, but it is NOT one of the
//! pure-Rust writers, so it is handled distinctly in [`convert_file`] and is
//! deliberately absent from [`supported_targets`]. It lowers the source to the
//! Markdown waypoint, renders the HTML exporter's self-contained output, and prints
//! it to PDF by driving a browser the user already has installed (Chrome or Edge),
//! detected at run time and never bundled (see the `pdf` module). Its availability
//! therefore depends on the host, reported by [`pdf_target_available`]. A host with
//! no suitable browser is refused by name ([`ConvertError::NoPdfEngine`]), never
//! handed an empty file; the pure-Rust Typst fallback for such hosts is a later
//! slice. This adds no crate dependency and never places a mark.

use crate::{extract_text, export, FileFormat, FilesError};

/// An error from a format-to-format conversion. Every variant names itself and its
/// target or source; no path returns empty or corrupt output silently (invariant 2).
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    /// The source document could not be extracted to the Markdown waypoint. The
    /// underlying file-layer error names the source format and the reason (an
    /// unreadable container, an image format that carries no document text, and so
    /// on). Surfaced unchanged rather than swallowed.
    #[error(transparent)]
    Source(#[from] FilesError),

    /// No pure-Rust exporter is shipped for this target in this build. Refused by
    /// name with the exact reason rather than approximated (invariant 2).
    #[error("converting to {target} is not supported in this build: {reason}")]
    UnsupportedTarget {
        target: &'static str,
        reason: String,
    },

    /// The exporter ran but could not keep its promise. Names the target. In this
    /// build the shipped exporters are infallible once the Markdown is in hand, so
    /// this is a guard for future writers rather than a path reached today.
    #[error("{target} export failed: {reason}")]
    Export {
        target: &'static str,
        reason: String,
    },

    /// No local browser suitable for PDF rendering was found. PDF (Phase D1) prints
    /// by driving a detected Chrome or Edge headless; when none is installed (or
    /// only Firefox, which has no headless print-to-PDF flag) this is refused BY
    /// NAME rather than producing an empty file (invariant 2). The pure-Rust Typst
    /// fallback (a later slice) is deliberately NOT bundled here.
    #[error("PDF rendering is unavailable: {detail}")]
    NoPdfEngine {
        detail: String,
    },
}

/// The target formats this build can convert TO, all pure Rust. Stable order.
///
/// Deferred targets (the binary containers, PDF, and the import-only or
/// non-document formats) are deliberately absent; [`convert_file`] refuses each by
/// name with [`unsupported_target_reason`].
pub fn supported_targets() -> Vec<FileFormat> {
    vec![
        FileFormat::Markdown,
        FileFormat::Html,
        FileFormat::PlainText,
        FileFormat::Latex,
        FileFormat::Rtf,
        FileFormat::Org,
        FileFormat::Rst,
        FileFormat::AsciiDoc,
        FileFormat::Ipynb,
        FileFormat::Typst,
    ]
}

/// True when [`convert_file`] can produce this target in this build.
///
/// This covers only the pure-Rust waypoint writers. PDF is a supported target too,
/// but browser-backed and handled distinctly, so it is intentionally NOT counted
/// here; probe it with [`pdf_target_available`] instead.
pub fn is_supported_target(target: FileFormat) -> bool {
    supported_targets().contains(&target)
}

/// Resolve an OUTPUT extension to a conversion target [`FileFormat`], `None` for an
/// extension that is not a conversion target.
///
/// This is the TARGET-side counterpart to [`FileFormat::from_extension`] (the
/// source-intake resolver). It is distinct on purpose: `.pdf` resolves HERE, to the
/// convert-target-only [`FileFormat::Pdf`], but stays unsupported as a SOURCE, so
/// PDF import remains refused by name. It covers the pure-Rust writers plus PDF; a
/// binary container or an import-only format returns `None`.
pub fn target_from_extension(ext: &str) -> Option<FileFormat> {
    Some(match ext.to_ascii_lowercase().as_str() {
        "md" | "markdown" | "mdown" | "mkd" => FileFormat::Markdown,
        "html" | "htm" | "xhtml" => FileFormat::Html,
        "txt" | "text" => FileFormat::PlainText,
        "tex" | "latex" => FileFormat::Latex,
        "rtf" => FileFormat::Rtf,
        "org" => FileFormat::Org,
        "rst" => FileFormat::Rst,
        "adoc" | "asciidoc" | "asc" => FileFormat::AsciiDoc,
        "ipynb" => FileFormat::Ipynb,
        "typ" => FileFormat::Typst,
        "pdf" => FileFormat::Pdf,
        _ => return None,
    })
}

/// Convert a document from `source` to `target`, best-effort and DECLARED LOSSY.
///
/// The source bytes are extracted to a Markdown waypoint (reusing the intake path),
/// then the target is regenerated from that Markdown with a copied pure-Rust
/// exporter. See the module doc for the losslessness contract and the marking
/// separation. Both failure modes are refused by name (invariant 2): a source that
/// cannot be extracted returns [`ConvertError::Source`]; a target with no exporter
/// returns [`ConvertError::UnsupportedTarget`].
pub fn convert_file(
    bytes: &[u8],
    source: FileFormat,
    target: FileFormat,
) -> Result<Vec<u8>, ConvertError> {
    // PDF is a browser-backed target (Phase D1), handled distinctly from the
    // pure-Rust waypoint writers below. It still lowers the source to the Markdown
    // waypoint and reuses the self-contained HTML exporter, but prints the result
    // through a DETECTED LOCAL BROWSER (a subprocess, never bundled). A PDF *source*
    // is refused by name upstream in `extract_text`.
    if target == FileFormat::Pdf {
        return convert_to_pdf(bytes, source);
    }

    // Refuse an unsupported target BEFORE extracting, so the caller gets the exact
    // reason even when the source would also have failed (the target gap is the
    // more actionable message for "convert X to <thing we don't do>").
    if !is_supported_target(target) {
        return Err(ConvertError::UnsupportedTarget {
            target: target_display(target),
            reason: unsupported_target_reason(target),
        });
    }

    // Extract to the Markdown waypoint. A source that carries no extractable text
    // (an image, an unreadable container) surfaces the file layer's named error.
    let extracted = extract_text(bytes, source)?;
    render_waypoint(&extracted.text, target)
}

/// Render an already-extracted Markdown waypoint to a supported pure-Rust target.
///
/// Shared by [`convert_file`] (source bytes lowered to this waypoint) and
/// [`export_text`] (a result string used directly as the waypoint). PDF and the
/// binary containers are NOT handled here; the caller gates them and this refuses
/// any other unshipped target by name (invariant 2).
fn render_waypoint(markdown: &str, target: FileFormat) -> Result<Vec<u8>, ConvertError> {
    let meta = export::ConvertMeta::default();
    let result = match target {
        FileFormat::Markdown => export::export_md(markdown),
        FileFormat::Html => export::export_html(markdown, &meta),
        FileFormat::PlainText => export::export_txt(markdown, &meta),
        FileFormat::Latex => export::export_tex(markdown, &meta),
        FileFormat::Rtf => export::export_rtf(markdown, &meta),
        FileFormat::Org => export::export_org(markdown, &meta),
        FileFormat::Rst => export::export_rst(markdown, &meta),
        FileFormat::AsciiDoc => export::export_adoc(markdown, &meta),
        FileFormat::Ipynb => export::export_ipynb(markdown, &meta),
        FileFormat::Typst => export::export_typst_src(markdown, &meta),
        // Unreachable when reached through the two callers, which both gate the
        // target first; kept as a named refusal rather than a panic.
        other => {
            return Err(ConvertError::UnsupportedTarget {
                target: target_display(other),
                reason: unsupported_target_reason(other),
            })
        }
    };

    result.map_err(|reason| ConvertError::Export {
        target: target_display(target),
        reason,
    })
}

/// Export a result STRING to a chosen format, treating the string as the Markdown
/// waypoint directly (no source extraction).
///
/// This is the universal-export primitive: it hands any text result (a revealed
/// secret, a marked cover, a report) back in a chosen format. It is DECLARED LOSSY
/// for the rich targets exactly as [`convert_file`] is, and byte-faithful only for
/// Markdown and plain text; the richer targets are a rendering, so a marked text's
/// whitespace or invisible carriers may not survive a rich target and the caller
/// must treat Markdown or plain text as the lossless choices. An unsupported target
/// (a binary container, or PDF which has its own native path) is refused by name
/// (invariant 2).
pub fn export_text(content: &str, target: FileFormat) -> Result<Vec<u8>, ConvertError> {
    match target {
        // Byte-faithful passthrough. The waypoint writers parse the content as
        // Markdown and re-render it, which normalises whitespace and drops any
        // invisible codepoint, so they are the wrong path for a marked text. For
        // plain text and Markdown the result IS the output: the exact bytes, so a
        // marked cover's whitespace and invisible carriers survive untouched. These
        // are therefore the lossless export choices, the rich targets a rendering.
        FileFormat::PlainText | FileFormat::Markdown => Ok(content.as_bytes().to_vec()),
        // Native PDF: a self-contained, pure-Rust rendering with the base-14
        // Helvetica font, no external process and no bundled font. It is a
        // declared-lossy rendering (a marked cover's hidden layer does not survive
        // it, and it is Latin-1); see the pdf_native module contract.
        FileFormat::Pdf => Ok(crate::pdf_native::text_to_pdf(content)),
        _ => {
            if !is_supported_target(target) {
                return Err(ConvertError::UnsupportedTarget {
                    target: target_display(target),
                    reason: unsupported_target_reason(target),
                });
            }
            render_waypoint(content, target)
        }
    }
}

/// True when this host can render PDF, i.e. a local browser suitable for headless
/// PDF printing (Chrome or Edge) is installed. Firefox does not count: Gecko has no
/// headless print-to-PDF flag. A caller/UI can use this to decide whether to OFFER
/// PDF as a target; [`convert_file`] refuses by name when it is `false`.
pub fn pdf_target_available() -> bool {
    crate::pdf::pdf_target_available()
}

/// The PDF branch of [`convert_file`]: lower the source to the Markdown waypoint,
/// render it to self-contained HTML with the existing exporter, and print that HTML
/// to PDF by driving a detected local browser. Both failure classes are named
/// (invariant 2): a source that carries no extractable text surfaces the file
/// layer's error; a host with no usable browser returns [`ConvertError::NoPdfEngine`].
fn convert_to_pdf(bytes: &[u8], source: FileFormat) -> Result<Vec<u8>, ConvertError> {
    // Extract to the Markdown waypoint. A PDF source (or an image) is refused by
    // name here rather than producing anything.
    let extracted = extract_text(bytes, source)?;
    let meta = export::ConvertMeta::default();

    // Reuse the self-contained HTML exporter as the print source.
    let html_bytes = export::export_html(&extracted.text, &meta).map_err(|reason| {
        ConvertError::Export {
            target: "PDF",
            reason: format!("HTML waypoint render failed: {reason}"),
        }
    })?;
    let html = String::from_utf8(html_bytes).map_err(|e| ConvertError::Export {
        target: "PDF",
        reason: format!("HTML waypoint was not valid UTF-8: {e}"),
    })?;

    crate::pdf::html_to_pdf(&html).map_err(map_pdf_error)
}

/// Map a `pdf` module error onto the conversion error surface. A missing engine is
/// its own named variant; every other browser-run failure names PDF as the target.
fn map_pdf_error(err: crate::pdf::PdfError) -> ConvertError {
    match err {
        crate::pdf::PdfError::NoUsableEngine { detail } => ConvertError::NoPdfEngine { detail },
        other => ConvertError::Export {
            target: "PDF",
            reason: other.to_string(),
        },
    }
}

/// A stable display name for a target, for error messages.
fn target_display(target: FileFormat) -> &'static str {
    match target {
        FileFormat::Docx => "DOCX",
        FileFormat::Odt => "ODT",
        FileFormat::Pptx => "PPTX",
        FileFormat::Epub => "EPUB",
        FileFormat::Html => "HTML",
        FileFormat::Markdown => "Markdown",
        FileFormat::Rtf => "RTF",
        FileFormat::Latex => "LaTeX",
        FileFormat::Org => "Org",
        FileFormat::Rst => "reStructuredText",
        FileFormat::Wiki => "MediaWiki",
        FileFormat::AsciiDoc => "AsciiDoc",
        FileFormat::Typst => "Typst source",
        FileFormat::Ipynb => "Jupyter",
        FileFormat::Bibtex => "BibTeX",
        FileFormat::Fb2 => "FictionBook",
        FileFormat::Eml => "email",
        FileFormat::Csv => "CSV",
        FileFormat::Code(_) => "source code",
        FileFormat::PlainText => "plain text",
        FileFormat::Png => "PNG",
        FileFormat::Svg => "SVG",
        FileFormat::Jpeg => "JPEG",
        FileFormat::Tiff => "TIFF",
        FileFormat::Webp => "WebP",
        FileFormat::Pdf => "PDF",
    }
}

/// The exact reason a target is not one of the pure-Rust conversion outputs in this
/// build. Named per family so a caller learns whether it is a dependency exclusion
/// (the containers) or a genuine gap in the reused engine. PDF is a special case: it
/// IS a conversion target, just a browser-backed one handled outside this list (see
/// [`convert_file`] and [`pdf_target_available`]), so the reason here says so rather
/// than claiming it is unsupported.
pub fn unsupported_target_reason(target: FileFormat) -> String {
    match target {
        FileFormat::Docx | FileFormat::Odt | FileFormat::Epub => {
            "the reused the upstream converter exporter for this container links the Typst equation-image \
             renderer (typst, typst-render, typst-svg, typst-assets) and the image crate for \
             figure embedding, which this build excludes; a stripped, text-only container writer \
             is a later slice"
                .to_string()
        }
        FileFormat::Pptx => {
            "the reused engine imports PowerPoint but ships no PPTX exporter; slide layout is not \
             a Markdown-waypoint target"
                .to_string()
        }
        FileFormat::Png | FileFormat::Svg | FileFormat::Jpeg | FileFormat::Tiff | FileFormat::Webp => {
            "an image format is not a document conversion target; its provenance rides the \
             metadata channel, not the text pipeline"
                .to_string()
        }
        FileFormat::Wiki => {
            "MediaWiki is import-only in the reused engine; there is no exporter to copy"
                .to_string()
        }
        FileFormat::Bibtex | FileFormat::Fb2 | FileFormat::Eml | FileFormat::Csv | FileFormat::Code(_) => {
            "the reused engine imports this format but ships no exporter for it; it is an intake \
             format, not a conversion target in this build"
                .to_string()
        }
        // PDF is a supported target, just not a pure-Rust writer: it is rendered by
        // driving a detected local browser (Phase D1), handled outside this list.
        FileFormat::Pdf => {
            "PDF is a supported conversion target, produced by driving a detected local browser \
             (Chrome or Edge) headless rather than a pure-Rust writer; its availability depends \
             on such a browser being installed (see pdf_target_available)"
                .to_string()
        }
        // The supported targets never reach here; return an honest fallback rather
        // than claim a reason for a format that actually works.
        FileFormat::Markdown
        | FileFormat::Html
        | FileFormat::PlainText
        | FileFormat::Latex
        | FileFormat::Rtf
        | FileFormat::Org
        | FileFormat::Rst
        | FileFormat::AsciiDoc
        | FileFormat::Ipynb
        | FileFormat::Typst => {
            "this target is supported; no reason applies".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::PdfError;

    #[test]
    fn no_usable_engine_maps_to_the_named_no_pdf_engine_error() {
        // Host-independent: a missing engine becomes ConvertError::NoPdfEngine,
        // carrying its detail, rather than a generic export failure.
        let mapped = map_pdf_error(PdfError::NoUsableEngine {
            detail: "no installed browser was found".to_string(),
        });
        match mapped {
            ConvertError::NoPdfEngine { detail } => {
                assert!(detail.contains("no installed browser"), "detail lost: {detail}");
            }
            other => panic!("expected NoPdfEngine, got {other:?}"),
        }
    }

    #[test]
    fn a_browser_run_failure_maps_to_a_named_pdf_export_error() {
        // Any other browser-run failure names PDF as the target, never silently.
        let mapped = map_pdf_error(PdfError::EmptyOutput {
            detail: "the browser produced an empty PDF file".to_string(),
        });
        match mapped {
            ConvertError::Export { target, reason } => {
                assert_eq!(target, "PDF");
                assert!(reason.contains("empty PDF"), "reason lost: {reason}");
            }
            other => panic!("expected Export naming PDF, got {other:?}"),
        }
    }

    #[test]
    fn pdf_is_never_reported_as_an_unsupported_target() {
        // PDF is a supported (browser-backed) target; is_supported_target gates only
        // the pure-Rust writers, and convert_file handles PDF before that gate.
        assert!(!is_supported_target(FileFormat::Pdf));
        assert_eq!(target_display(FileFormat::Pdf), "PDF");
    }

    #[test]
    fn target_resolver_maps_pdf_but_source_resolver_does_not() {
        // The TARGET resolver names PDF (a convert output); the SOURCE resolver still
        // refuses it (import stays unsupported). The two are deliberately separate.
        assert_eq!(target_from_extension("pdf"), Some(FileFormat::Pdf));
        assert_eq!(target_from_extension("PDF"), Some(FileFormat::Pdf));
        assert_eq!(target_from_extension("md"), Some(FileFormat::Markdown));
        // A binary container is not a target here.
        assert_eq!(target_from_extension("docx"), None);
        // And PDF is NOT a source format.
        assert!(FileFormat::from_extension("pdf").is_err());
    }

    #[test]
    fn export_text_is_byte_faithful_for_plain_text_and_markdown() {
        // Plain text and Markdown are the lossless choices: the exact content comes
        // back, invisible carriers and all. This content carries a zero-width space
        // (U+200B) and a run of spaces, exactly the kind of hidden layer a marked
        // cover holds; both must survive so an exported marked text stays decodable.
        let content = "The meeting is\u{200B} at dawn.\nBring   the documents.";
        let txt = export_text(content, FileFormat::PlainText).expect("txt export");
        assert_eq!(String::from_utf8(txt).unwrap(), content, "txt export is byte-faithful");
        let md = export_text(content, FileFormat::Markdown).expect("md export");
        assert_eq!(String::from_utf8(md).unwrap(), content, "md export is byte-faithful");
    }

    #[test]
    fn export_text_produces_every_supported_target_non_empty() {
        // Every pure-Rust target renders a non-empty document from a result string.
        let content = "# Report\n\nOne finding, stated plainly.";
        for target in supported_targets() {
            let out = export_text(content, target)
                .unwrap_or_else(|e| panic!("export to {target:?} must succeed: {e}"));
            assert!(!out.is_empty(), "export to {target:?} must not be empty");
        }
    }

    #[test]
    fn export_text_carries_the_content_into_html() {
        // The HTML target embeds the result text rather than dropping it.
        let out = export_text("a distinctive phrase to find", FileFormat::Html).unwrap();
        let html = String::from_utf8(out).unwrap();
        assert!(html.contains("distinctive phrase"), "html carries the content");
    }

    #[test]
    fn export_text_refuses_a_binary_container_by_name() {
        // A target with no pure-Rust writer here (a DOCX) is refused by name, never
        // a silent empty file (invariant 2).
        let err = export_text("x", FileFormat::Docx).unwrap_err();
        assert!(matches!(err, ConvertError::UnsupportedTarget { .. }), "docx refused by name");
    }

    #[test]
    fn export_text_produces_a_native_pdf() {
        // PDF now exports through the self-contained native writer, no browser and
        // no bundled font.
        let pdf = export_text("a short report", FileFormat::Pdf).expect("native pdf export");
        assert!(pdf.starts_with(b"%PDF"), "the export is a PDF document");
    }
}
